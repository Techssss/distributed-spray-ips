from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from itertools import combinations
from time import monotonic


@dataclass(frozen=True)
class Failure:
    ip: str
    account: str
    surface: str
    at: float


@dataclass(frozen=True)
class Campaign:
    sources: tuple[str, ...]
    targets: tuple[str, ...]
    surfaces: tuple[str, ...]


class SprayDetector:
    def __init__(self, window=60, threshold=5, clock=monotonic):
        self.window = window
        self.threshold = threshold
        self.clock = clock
        self.failures = deque(maxlen=512)

    def record_failure(self, ip, account, surface):
        self.failures.append(Failure(ip, account, surface, self.clock()))

    def signals(self):
        cutoff = self.clock() - self.window
        while self.failures and self.failures[0].at <= cutoff:
            self.failures.popleft()

        ip_counts = Counter(event.ip for event in self.failures)
        account_counts = Counter(event.account for event in self.failures)
        return {
            'ip_threshold': sorted(ip for ip, count in ip_counts.items() if count >= self.threshold),
            'account_threshold': sorted(
                account for account, count in account_counts.items() if count >= self.threshold
            ),
            'campaigns': self._campaigns(),
        }

    def _campaigns(self):
        # The bipartite graph links each source IP to each account it failed against.
        sources_by_account = defaultdict(set)
        for event in self.failures:
            sources_by_account[event.account].add(event.ip)

        overlap = Counter()
        for sources in sources_by_account.values():
            overlap.update(combinations(sorted(sources), 2))

        # IPs become neighbors only if they share at least two distinct targets.
        neighbors = defaultdict(set)
        for (left, right), shared in overlap.items():
            if shared >= 2:
                neighbors[left].add(right)
                neighbors[right].add(left)

        campaigns = []
        unseen = set(neighbors)
        while unseen:
            pending = [min(unseen)]
            component = set()
            while pending:
                ip = pending.pop()
                if ip not in unseen:
                    continue
                unseen.remove(ip)
                component.add(ip)
                pending.extend(neighbors[ip] & unseen)

            if len(component) < 3:
                continue
            targets = {
                account for account, sources in sources_by_account.items()
                if len(sources & component) >= 2
            }
            if len(targets) < 3:
                continue
            surfaces = {
                event.surface for event in self.failures
                if event.ip in component and event.account in targets
            }
            campaigns.append(Campaign(tuple(sorted(component)), tuple(sorted(targets)), tuple(sorted(surfaces))))
        return campaigns
