import uuid
from collections import deque

from pyvoip.lib.models import Message


class Q:
    """
    A simple queue implementation to allow sending messages to the
    controlling application in a thread-safe manner and correct order.

    ! Important, only append and popleft method are thread-safe.
    """

    def __init__(self):
        self._items: deque = deque()

    def __len__(self) -> int:
        return len(self._items)

    def __contains__(self, item) -> bool:
        return item in self._items

    def __iter__(self):
        yield from self._items

    def __reversed__(self):
        yield from reversed(self._items)

    def __repr__(self) -> str:
        return f"Queue({list(self._items)})"


class MsgQ(Q):
    """
    A simple queue handling messages. This is a subclass of Q.
    """

    def __init__(self):
        super().__init__()

    def enq(self, item: Message) -> None:
        self._items.append(item)

    def deq(self) -> Message | None:
        try:
            return self._items.popleft()
        except IndexError:
            return None  # Message(id=0, text="")

    # def deqn(self, n: int = 1) -> str:
    #     return "".join(self.deq().text for _ in range())


class StrQ(Q):
    """
    A simple queue handling strings. This is a subclass of Q.
    """

    def __init__(self):
        super().__init__()

    def enq(self, item: str) -> None:
        self._items.append(item)

    def deq(self) -> str:
        try:
            return self._items.popleft()
        except IndexError:
            return ""

    def deqn(self, n: int = 1) -> str:
        return "".join(self.deq() for _ in range())


class Counter:
    def __init__(self, start: int = 1):
        self.x = start

    def count(self) -> int:
        x = self.x
        self.x += 1
        return x

    def next(self) -> int:
        return self.count()

    def current(self) -> int:
        return self.x
