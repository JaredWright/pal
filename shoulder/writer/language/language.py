import abc
from typing import TextIO
from typing import List
from typing import Any

from shoulder.model.register import Register
from shoulder.model.fieldset import Fieldset
from shoulder.model.field import Field


class LanguageWriter(abc.ABC):

    @abc.abstractmethod
    def declare_comment(self, outfile: TextIO, comment: str) -> None:
        pass

    @abc.abstractmethod
    def declare_register_constants(self, outfile: TextIO, register: Register) -> None:
        pass

    @abc.abstractmethod
    def declare_register_get(self, outfile: TextIO, register: Register) -> None:
        pass

    @abc.abstractmethod
    def declare_register_set(self, outfile: TextIO, register: Register) -> None:
        pass

    @abc.abstractmethod
    def declare_field_constants(self, outfile: TextIO, register: Register,
                                field: Field) -> None:
        pass

    @abc.abstractmethod
    def declare_field_accessors(self, outfile: TextIO, register: Register,
                                field: Field) -> None:
        pass

    @abc.abstractmethod
    def declare_field_print(self, outfile: TextIO, register: Register,
                            field: Field) -> None:
        pass

    @abc.abstractmethod
    def declare_fieldset_print(self, outfile: TextIO, register: Register,
                               fieldset: Fieldset) -> None:
        pass
