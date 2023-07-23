NONE_VALUES = ['', ' ', None, 'none', 'None']


class FilterModule(object):
    def filters(self):
        return {
            "ensure_list": self.ensure_list,
            "extend_list": self.extend_list,
            "nftables_format_counter": self.nftables_format_counter,
            "nftables_format_limit": self.nftables_format_limit,
            "nftables_format_set": self.nftables_format_set,
        }

    @staticmethod
    def ensure_list(data: (str, list)) -> list:
        if isinstance(data, list):
            return data

        return [data]

    @classmethod
    def extend_list(cls, l1: list, l2: list) -> list:
        l1 = cls.ensure_list(l1)
        l1.extend(cls.ensure_list(l2))
        return l1

    @classmethod
    def nftables_format_set(cls, config: dict, whitespace: int) -> str:
        lines = []

        if 'typeof' in config:
            lines.append(f"typeof {config['typeof']}")

        else:
            lines.append(f"type {config['type']}")

        _flags = cls.ensure_list(config['flags'])
        if len(_flags) > 0:
            lines.append(f"flags {', '.join(map(str, cls.ensure_list(_flags)))}")

            for k, v in config['settings'].items():
                lines.append(f"{k} {v}")

        if config['counter']:
            lines.append('counter')

        return cls._format_lines(whitespace=whitespace, lines=lines)

    @staticmethod
    def _format_lines(lines: list, whitespace: int) -> str:
        return f"\n{' ' * whitespace}".join(lines)

    @staticmethod
    def _format_comment(comment: str) -> str:
        return f"comment \"{comment}\""

    @classmethod
    def nftables_format_counter(cls, config: dict, whitespace: int) -> str:
        lines = []

        if 'comment' in config:
            lines.append(cls._format_comment(config['comment']))

        return cls._format_lines(whitespace=whitespace, lines=lines)

    @classmethod
    def nftables_format_limit(cls, config: dict, whitespace: int) -> str:
        lines = [f"rate {config['rate']}"]

        if 'comment' in config:
            lines.append(cls._format_comment(config['comment']))

        return cls._format_lines(whitespace=whitespace, lines=lines)
