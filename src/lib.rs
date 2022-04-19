// Copyright (c) 2022 Espresso Systems (espressosys.com)
// This file is part of the KeySet library.

// This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
// This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
// You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

#![deny(warnings)]

use ark_serialize::*;
use commit::{Commitment, Committable};
use core::fmt::Debug;
use jf_cap::{
    proof::{freeze::FreezeProvingKey, mint::MintProvingKey, transfer::TransferProvingKey},
    TransactionVerifyingKey,
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;
use snafu::Snafu;
use std::collections::BTreeMap;
use std::iter::FromIterator;
use std::ops::Bound::*;

#[derive(Debug, Snafu)]
#[snafu(visibility(pub))]
pub enum Error {
    DuplicateKeys {
        num_inputs: usize,
        num_outputs: usize,
    },
    NoKeys,
}

pub trait SizedKey: CanonicalSerialize + CanonicalDeserialize {
    fn num_inputs(&self) -> usize;
    fn num_outputs(&self) -> usize;
}

impl<'a> SizedKey for TransferProvingKey<'a> {
    fn num_inputs(&self) -> usize {
        self.num_input()
    }

    fn num_outputs(&self) -> usize {
        self.num_output()
    }
}

impl<'a> SizedKey for FreezeProvingKey<'a> {
    fn num_inputs(&self) -> usize {
        self.num_input()
    }

    fn num_outputs(&self) -> usize {
        self.num_output()
    }
}

impl SizedKey for TransactionVerifyingKey {
    fn num_inputs(&self) -> usize {
        match self {
            TransactionVerifyingKey::Transfer(xfr) => xfr.num_input(),
            TransactionVerifyingKey::Freeze(freeze) => freeze.num_input(),
            TransactionVerifyingKey::Mint(_) => 1,
        }
    }

    fn num_outputs(&self) -> usize {
        match self {
            TransactionVerifyingKey::Transfer(xfr) => xfr.num_output(),
            TransactionVerifyingKey::Freeze(freeze) => freeze.num_output(),
            TransactionVerifyingKey::Mint(_) => 2,
        }
    }
}

pub trait KeyOrder {
    type SortKey: Ord
        + Debug
        + Clone
        + Serialize
        + for<'a> Deserialize<'a>
        + CanonicalSerialize
        + CanonicalDeserialize;
    fn sort_key(num_inputs: usize, num_outputs: usize) -> Self::SortKey;
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrderByInputs;
impl KeyOrder for OrderByInputs {
    type SortKey = (usize, usize);
    fn sort_key(num_inputs: usize, num_outputs: usize) -> Self::SortKey {
        (num_inputs, num_outputs)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OrderByOutputs;
impl KeyOrder for OrderByOutputs {
    type SortKey = (usize, usize);
    fn sort_key(num_inputs: usize, num_outputs: usize) -> Self::SortKey {
        (num_outputs, num_inputs)
    }
}

#[serde_as]
#[derive(
    Debug,
    Default,
    Clone,
    Serialize,
    Deserialize,
    CanonicalSerialize,
    CanonicalDeserialize,
    PartialEq,
)]
#[serde(bound = "K: Serialize + for<'a> Deserialize<'a>")]
pub struct KeySet<K: SizedKey, Order: KeyOrder = OrderByInputs> {
    // serde_json does not support maps where the keys are not Strings (or easily convertible
    // to/from Strings) so we serialize this map as a sequence of key-value pairs.
    #[serde_as(as = "Vec<(_, _)>")]
    keys: BTreeMap<Order::SortKey, K>,
}

impl<K: SizedKey, Order: KeyOrder> KeySet<K, Order> {
    /// Create a new KeySet with the keys in an iterator. `keys` must contain at least one key,
    /// and it must not contain two keys with the same size.
    pub fn new(keys: impl Iterator<Item = K>) -> Result<Self, Error> {
        let mut map = BTreeMap::new();
        for key in keys {
            let sort_key = Order::sort_key(key.num_inputs(), key.num_outputs());
            if map.contains_key(&sort_key) {
                return Err(Error::DuplicateKeys {
                    num_inputs: key.num_inputs(),
                    num_outputs: key.num_outputs(),
                });
            }
            map.insert(sort_key, key);
        }
        if map.is_empty() {
            return Err(Error::NoKeys);
        }
        Ok(Self { keys: map })
    }

    /// Get the largest size supported by this KeySet.
    ///
    /// Panics if there are no keys in the KeySet. Since new() requires at least one key, this
    /// can only happen if the KeySet is corrupt (for example, it was deserialized from a
    /// corrupted file).
    pub fn max_size(&self) -> (usize, usize) {
        let key = &self.keys.iter().next_back().unwrap().1;
        (key.num_inputs(), key.num_outputs())
    }

    pub fn key_for_size(&self, num_inputs: usize, num_outputs: usize) -> Option<&K> {
        self.keys.get(&Order::sort_key(num_inputs, num_outputs))
    }

    /// Return the smallest key whose size is at least (num_inputs, num_outputs). If no such key
    /// is available, the error contains the largest size that could have been supported.
    pub fn best_fit_key(
        &self,
        num_inputs: usize,
        num_outputs: usize,
    ) -> Result<(usize, usize, &K), (usize, usize)> {
        self.keys
            .range((
                Included(Order::sort_key(num_inputs, num_outputs)),
                Unbounded,
            ))
            // We are not guaranteed that everything in this range has `inputs >= num_inputs` _and_
            // `outputs >= num_outputs`. For example, if `Order` is `OrderByInputs`, everything in
            // the range has `inputs >= num_inputs`, but not necessarily `outputs >= num_outputs`,
            // since, e.g. (3, 1) >= (2, 2) even though 1 < 2. Therefore, we need to iterate over
            // the range to find the first key that satisfies both constraints.
            .find_map(|(_, key)| {
                let key_inputs = key.num_inputs();
                let key_outputs = key.num_outputs();
                if key_inputs >= num_inputs && key_outputs >= num_outputs {
                    Some((key_inputs, key_outputs, key))
                } else {
                    None
                }
            })
            .ok_or_else(|| self.max_size())
    }

    /// Return the key whose size is (num_inputs, num_outputs).
    pub fn exact_fit_key(&self, num_inputs: usize, num_outputs: usize) -> Option<&K> {
        self.keys.get(&Order::sort_key(num_inputs, num_outputs))
    }

    pub fn iter(&self) -> impl Iterator<Item = &K> {
        self.keys.values()
    }
}

impl<K: SizedKey, Order: KeyOrder> FromIterator<K> for KeySet<K, Order> {
    fn from_iter<T: IntoIterator<Item = K>>(iter: T) -> Self {
        Self::new(iter.into_iter()).unwrap()
    }
}

#[derive(
    Debug, Clone, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize, PartialEq,
)]
pub struct ProverKeySet<'a, Order: KeyOrder = OrderByInputs> {
    pub mint: MintProvingKey<'a>,
    pub xfr: KeySet<TransferProvingKey<'a>, Order>,
    pub freeze: KeySet<FreezeProvingKey<'a>, Order>,
}

#[derive(Debug, Clone, CanonicalSerialize, CanonicalDeserialize, Serialize, Deserialize)]
pub struct VerifierKeySet<Order: KeyOrder = OrderByInputs> {
    // TODO: is there a way to keep these types distinct?
    pub mint: TransactionVerifyingKey,
    pub xfr: KeySet<TransactionVerifyingKey, Order>,
    pub freeze: KeySet<TransactionVerifyingKey, Order>,
}

impl Committable for VerifierKeySet {
    fn commit(&self) -> Commitment<Self> {
        commit::RawCommitmentBuilder::new("VerifCRS Comm")
            .var_size_bytes(&bincode::serialize(self).unwrap())
            .finalize()
    }
}
