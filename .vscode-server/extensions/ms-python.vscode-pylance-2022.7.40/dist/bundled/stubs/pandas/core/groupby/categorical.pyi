from pandas.core.arrays.categorical import (  # , CategoricalDtype as CategoricalDtype
    Categorical as Categorical,
)

def recode_for_groupby(c: Categorical, sort: bool, observed: bool): ...
def recode_from_groupby(c: Categorical, sort: bool, ci): ...