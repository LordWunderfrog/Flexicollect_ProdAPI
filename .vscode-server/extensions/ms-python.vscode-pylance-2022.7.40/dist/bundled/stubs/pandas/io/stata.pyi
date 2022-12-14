from collections import abc
import datetime
from typing import (
    Dict,
    Hashable,
    List,
    Optional,
    Sequence,
)

from pandas.core.frame import DataFrame

from pandas._typing import FilePathOrBuffer

def read_stata(
    path: FilePathOrBuffer,
    convert_dates: bool = ...,
    convert_categoricals: bool = ...,
    index_col: Optional[str] = ...,
    convert_missing: bool = ...,
    preserve_dtypes: bool = ...,
    columns: Optional[List[str]] = ...,
    order_categoricals: bool = ...,
    chunksize: Optional[int] = ...,
    iterator: bool = ...,
) -> DataFrame:
    """
Read Stata file into DataFrame.

Parameters
----------
filepath_or_buffer : str, path object or file-like object
    Any valid string path is acceptable. The string could be a URL. Valid
    URL schemes include http, ftp, s3, and file. For file URLs, a host is
    expected. A local file could be: ``file://localhost/path/to/table.dta``.

    If you want to pass in a path object, pandas accepts any ``os.PathLike``.

    By file-like object, we refer to objects with a ``read()`` method,
    such as a file handle (e.g. via builtin ``open`` function)
    or ``StringIO``.
convert_dates : bool, default True
    Convert date variables to DataFrame time values.
convert_categoricals : bool, default True
    Read value labels and convert columns to Categorical/Factor variables.
index_col : str, optional
    Column to set as index.
convert_missing : bool, default False
    Flag indicating whether to convert missing values to their Stata
    representations.  If False, missing values are replaced with nan.
    If True, columns containing missing values are returned with
    object data types and missing values are represented by
    StataMissingValue objects.
preserve_dtypes : bool, default True
    Preserve Stata datatypes. If False, numeric data are upcast to pandas
    default types for foreign data (float64 or int64).
columns : list or None
    Columns to retain.  Columns will be returned in the given order.  None
    returns all columns.
order_categoricals : bool, default True
    Flag indicating whether converted categorical data are ordered.
chunksize : int, default None
    Return StataReader object for iterations, returns chunks with
    given number of lines.
iterator : bool, default False
    Return StataReader object.
compression : str or dict, default 'infer'
    For on-the-fly decompression of on-disk data. If 'infer' and '%s' is
    path-like, then detect compression from the following extensions: '.gz',
    '.bz2', '.zip', '.xz', or '.zst' (otherwise no compression). If using
    'zip', the ZIP file must contain only one data file to be read in. Set to
    ``None`` for no decompression. Can also be a dict with key ``'method'`` set
    to one of {``'zip'``, ``'gzip'``, ``'bz2'``, ``'zstd'``} and other
    key-value pairs are forwarded to ``zipfile.ZipFile``, ``gzip.GzipFile``,
    ``bz2.BZ2File``, or ``zstandard.ZstdDecompressor``, respectively. As an
    example, the following could be passed for Zstandard decompression using a
    custom compression dictionary:
    ``compression={'method': 'zstd', 'dict_data': my_compression_dict}``.
storage_options : dict, optional
    Extra options that make sense for a particular storage connection, e.g.
    host, port, username, password, etc. For HTTP(S) URLs the key-value pairs
    are forwarded to ``urllib`` as header options. For other URLs (e.g.
    starting with "s3://", and "gcs://") the key-value pairs are forwarded to
    ``fsspec``. Please see ``fsspec`` and ``urllib`` for more details.

Returns
-------
DataFrame or StataReader

See Also
--------
io.stata.StataReader : Low-level reader for Stata data files.
DataFrame.to_stata: Export Stata data files.

Notes
-----
Categorical variables read through an iterator may not have the same
categories and dtype. This occurs when  a variable stored in a DTA
file is associated to an incomplete set of value labels that only
label a strict subset of the values.

Examples
--------

Creating a dummy stata for this example
>>> df = pd.DataFrame({'animal': ['falcon', 'parrot', 'falcon',
...                              'parrot'],
...                   'speed': [350, 18, 361, 15]})  # doctest: +SKIP
>>> df.to_stata('animals.dta')  # doctest: +SKIP

Read a Stata dta file:

>>> df = pd.read_stata('animals.dta')  # doctest: +SKIP

Read a Stata dta file in 10,000 line chunks:
>>> values = np.random.randint(0, 10, size=(20_000, 1), dtype="uint8")  # doctest: +SKIP
>>> df = pd.DataFrame(values, columns=["i"])  # doctest: +SKIP
>>> df.to_stata('filename.dta')  # doctest: +SKIP

>>> itr = pd.read_stata('filename.dta', chunksize=10000)  # doctest: +SKIP
>>> for chunk in itr:
...    # Operate on a single chunk, e.g., chunk.mean()
...    pass  # doctest: +SKIP
    """
    pass

stata_epoch = ...
excessive_string_length_error: str

class PossiblePrecisionLoss(Warning): ...

precision_loss_doc: str

class ValueLabelTypeMismatch(Warning): ...

value_label_mismatch_doc: str

class InvalidColumnName(Warning): ...

invalid_name_doc: str

class StataValueLabel:
    labname = ...
    value_labels = ...
    text_len = ...
    off = ...
    val = ...
    txt = ...
    n: int = ...
    len = ...
    def __init__(self, catarray, encoding: str = ...): ...
    def generate_value_label(self, byteorder): ...

class StataMissingValue:
    MISSING_VALUES = ...
    bases = ...
    float32_base: bytes = ...
    increment = ...
    value = ...
    int_value = ...
    float64_base: bytes = ...
    BASE_MISSING_VALUES = ...
    def __init__(self, value) -> None: ...
    string = ...
    def __eq__(self, other) -> bool: ...
    @classmethod
    def get_base_missing_value(cls, dtype): ...

class StataParser:
    DTYPE_MAP = ...
    DTYPE_MAP_XML = ...
    TYPE_MAP = ...
    TYPE_MAP_XML = ...
    VALID_RANGE = ...
    OLD_TYPE_MAPPING = ...
    MISSING_VALUES = ...
    NUMPY_TYPE_MAP = ...
    RESERVED_WORDS = ...
    def __init__(self) -> None: ...

class StataReader(StataParser, abc.Iterator):
    col_sizes = ...
    path_or_buf = ...
    def __init__(
        self,
        path_or_buf,
        convert_dates: bool = ...,
        convert_categoricals: bool = ...,
        index_col=...,
        convert_missing: bool = ...,
        preserve_dtypes: bool = ...,
        columns=...,
        order_categoricals: bool = ...,
        chunksize=...,
    ) -> None: ...
    def __enter__(self): ...
    def __exit__(self, exc_type, exc_value, traceback) -> None: ...
    def close(self) -> None: ...
    def __next__(self): ...
    def get_chunk(self, size=...): ...
    def read(
        self,
        nrows=...,
        convert_dates=...,
        convert_categoricals=...,
        index_col=...,
        convert_missing=...,
        preserve_dtypes=...,
        columns=...,
        order_categoricals=...,
    ): ...
    @property
    def data_label(self): ...
    def variable_labels(self): ...
    def value_labels(self): ...

class StataWriter(StataParser):
    type_converters = ...
    def __init__(
        self,
        fname,
        data,
        convert_dates=...,
        write_index: bool = ...,
        byteorder=...,
        time_stamp=...,
        data_label=...,
        variable_labels=...,
    ) -> None: ...
    def write_file(self) -> None: ...

class StataStrLWriter:
    df = ...
    columns = ...
    def __init__(self, df, columns, version: int = ..., byteorder=...) -> None: ...
    def generate_table(self): ...
    def generate_blob(self, gso_table): ...

class StataWriter117(StataWriter):
    def __init__(
        self,
        fname,
        data,
        convert_dates=...,
        write_index: bool = ...,
        byteorder=...,
        time_stamp=...,
        data_label=...,
        variable_labels=...,
        convert_strl=...,
    ) -> None: ...

class StataWriterUTF8(StataWriter117):
    def __init__(
        self,
        fname: FilePathOrBuffer,
        data: DataFrame,
        convert_dates: Optional[Dict[Hashable, str]] = ...,
        write_index: bool = ...,
        byteorder: Optional[str] = ...,
        time_stamp: Optional[datetime.datetime] = ...,
        data_label: Optional[str] = ...,
        variable_labels: Optional[Dict[Hashable, str]] = ...,
        convert_strl: Optional[Sequence[Hashable]] = ...,
        version: Optional[int] = ...,
    ) -> None: ...
