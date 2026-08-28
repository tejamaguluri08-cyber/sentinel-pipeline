from abc import ABC, abstractmethod
class ScannerAdapter(ABC):
    @abstractmethod
    def parse(self, path): ...
