from re import sub as regex_replace


class FilterModule(object):

    def filters(self):
        return {
            "nftables_rules_translate": self.nftables_rules_translate,
            "nftables_rules_sort": self.nftables_rules_sort,
            "nftables_format_list": self.nftables_format_list,
            "nftables_format_var": self.nftables_format_var,
            "nftables_safe_name": self.nftables_safe_name,
            "ensure_list": self.ensure_list,
            "extend_list": self.extend_list,
        }

    @staticmethod
    def ensure_list(data: (str, list)) -> list:
        if isinstance(data, list):
            return data

        else:
            return [data]

    @classmethod
    def extend_list(cls, l1: list, l2: list) -> list:
        l1 = cls.ensure_list(l1)
        l1.extend(cls.ensure_list(l2))
        return l1

    @staticmethod
    def nftables_safe_name(name: str) -> str:
        return regex_replace('[^0-9a-zA-Z]+', '', name.replace(' ', '_'))

    @classmethod
    def nftables_rules_translate(cls, raw_rules: list, config: dict) -> list:
        rules = []
        NONE_VALUES = ['', ' ', None]

        for r in raw_rules:
            if isinstance(r, str):
                _rule = r

            elif not isinstance(r, dict):
                raise ValueError(
                    'Rule has unsupported format! Should be string or dict!'
                    f"Rule: {r}'"
                )

            elif 'raw' in r:
                _rule = r['raw']

            else:
                _translation = config['defaults'].copy()
                _field_mapping = {}

                for field_nft, fields_config in config['aliases'].items():
                    for field_config in fields_config:
                        if field_config in r:
                            _field_mapping[field_nft] = field_config
                            _value = r[field_config]

                            if isinstance(_value, list):
                                _value = cls.nftables_format_list(_value)

                            elif field_nft in config['quote'] and _value.find('"') == -1:
                                _value = f'"{_value}"'

                            if isinstance(_value, str):
                                _value.strip()

                            if field_nft not in NONE_VALUES:
                                _translation[field_nft] = f"{field_nft} {_value}"

                            else:
                                _translation[field_nft] = _value

                if config['drop_log'] and _translation['action'] == 'drop' and 'log prefix' not in _field_mapping:
                    # add generic logging for any dropped packets
                    if 'comment' in _translation:
                        _translation['log prefix'] = f"log prefix \"{_translation['comment']}\""

                    else:
                        _translation['log prefix'] = 'log'

                _rule = ''
                for field_nft in config['sequence']:
                    if field_nft in _translation:
                        _rule += f"{_translation[field_nft]} "

                _rule = _rule.strip()

            if _rule in NONE_VALUES:
                continue

            rules.append(_rule)

        return rules

    @staticmethod
    def nftables_rules_sort(raw_rules: list, config: dict) -> list:
        rules = []
        ordered = {}

        for r in raw_rules:
            _seq = None

            if isinstance(r, dict):
                for k in config['fields']:
                    if k in r:
                        _seq = r[k]
                        break

            if _seq is None:
                _seq = config['fallback']
                config['fallback'] += 1

            if _seq in ordered:
                raise ValueError(f"Got duplicate rule sequence: '{_seq}' in rule: {r}")

            ordered[_seq] = r

        sequence = list(ordered.keys())
        sequence.sort()

        for i in sequence:
            rules.append(ordered[i])

        return rules

    @classmethod
    def nftables_format_list(cls, data: list) -> str:
        return f"{{ {', '.join(map(str, cls.ensure_list(data)))} }}"

    @classmethod
    def nftables_format_var(cls, key: str, value: (str, list)) -> str:
        return f"define { cls.nftables_safe_name(key) } = {cls.nftables_format_list(value)}"

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

        return f";\n{' ' * whitespace}".join(lines)
