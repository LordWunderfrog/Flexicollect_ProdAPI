from typing import (
    Tuple,
    Union,
)

import numpy as np
from pandas.core.indexes.api import Index

from pandas._libs.indexing import _NDFrameIndexerBase
from pandas._typing import (
    Scalar,
    StrLike,
)

class _IndexSlice:
    def __getitem__(self, arg) -> Tuple[Union[StrLike, Scalar, slice], ...]: ...

IndexSlice: _IndexSlice

class IndexingError(Exception): ...

class IndexingMixin:
    @property
    def iloc(self) -> _iLocIndexer: ...
    @property
    def loc(self) -> _LocIndexer: ...
    @property
    def at(self) -> _AtIndexer: ...
    @property
    def iat(self) -> _iAtIndexer: ...

class _NDFrameIndexer(_NDFrameIndexerBase):
    axis = ...
    def __call__(self, axis=...): ...
    def __getitem__(self, key): ...
    def __setitem__(self, key, value) -> None: ...

class _LocationIndexer(_NDFrameIndexer):
    def __getitem__(self, key): ...

class _LocIndexer(_LocationIndexer): ...
class _iLocIndexer(_LocationIndexer): ...

class _ScalarAccessIndexer(_NDFrameIndexerBase):
    def __getitem__(self, key): ...
    def __setitem__(self, key, value) -> None: ...

class _AtIndexer(_ScalarAccessIndexer): ...
class _iAtIndexer(_ScalarAccessIndexer): ...

def convert_to_index_sliceable(obj, key): ...
def check_bool_indexer(index: Index, key) -> np.ndarray: ...
def convert_missing_indexer(indexer): ...
def convert_from_missing_indexer_tuple(indexer, axes): ...
def maybe_convert_ix(*args): ...
def is_nested_tuple(tup, labels) -> bool: ...
def is_label_like(key) -> bool: ...
def need_slice(obj) -> bool: ...
