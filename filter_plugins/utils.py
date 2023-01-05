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
    def _translate_rule(cls, rule: dict, config: dict):
        translation = config['defaults'].copy()
        mapping = {}

        for field_dst, fields_src in config['aliases'].items():
            for field_src in fields_src:
                if field_src in rule:
                    mapping[field_dst] = field_src
                    value = rule[field_src]

                    if isinstance(value, list):
                        value = cls.nftables_format_list(value)

                    elif field_dst in config['quote'] and value.find('"') == -1:
                        value = f'"{value}"'

                    if isinstance(value, str):
                        value.strip()

                    if field_dst in config['remove']:
                        translation[field_dst] = value

                    else:
                        translation[field_dst] = f"{field_dst} {value}"

                    break

        # add generic logging for any dropped packets
        if config['drop_log'] and translation['action'] == 'drop' \
                and 'log prefix' not in mapping:
            if 'comment' in translation:
                _comment = translation['comment'].replace('comment ', '')

            else:
                _comment = f"\"{config['drop_log_prefix']}\""

            translation['log prefix'] = f"log prefix {_comment}"

        # concat the rule in its designated field-sequence
        translated_rule = ''
        for field_nft in config['sequence']:
            if field_nft in translation:
                translated_rule += f"{translation[field_nft]} "

        return translated_rule.strip()

    @classmethod
    def nftables_rules_translate(cls, raw_rules: list, translate_config: dict) -> list:
        rules = []
        NONE_VALUES = ['', ' ', None]

        for rule in raw_rules:
            # pass raw rules directly (either as 'raw' key or only string)
            if not isinstance(rule, (dict, str)):
                raise ValueError(
                    'Rule has unsupported format - should be string or dict! '
                    f"Rule: {rule}'"
                )

            elif isinstance(rule, str):
                _translated = rule

            elif 'raw' in rule:
                _translated = rule['raw']

            else:
                _translated = cls._translate_rule(
                    rule=rule,
                    config=translate_config,
                )

            if _translated in NONE_VALUES:
                continue

            rules.append(_translated)

        return rules

    @staticmethod
    def _get_sequence(rule: (dict, str), sort_config: dict) -> int:
        if isinstance(rule, dict):
            for k in sort_config['fields']:
                if k in rule:
                    return rule[k]

        sort_config['fallback'] += 1
        return sort_config['fallback']

    @staticmethod
    def nftables_merge_rules(rules: list, config: dict, table: dict, chain_name: str) -> list:
        if '_all' in config['_defaults']['rules']:
            rules.extend(config['_defaults']['rules']['_all'])

        if chain_name in config['_defaults']['rules']:
            rules.extend(config['_defaults']['rules'][chain_name])

        if '_all' in table['_defaults']['rules']:
            rules.extend(table['_defaults']['rules']['_all'])

        if chain_name in table['_defaults']['rules']:
            rules.extend(table['_defaults']['rules'][chain_name])

        return rules

    @classmethod
    def nftables_merge_sort_translate_rules(
            cls, rules: list, config: dict, table: dict, chain_name: str,
            config_hc: dict,
    ) -> list:
        rules = cls.nftables_merge_rules(
            rules=rules,
            config=config,
            table=table,
            chain_name=chain_name,
        )
        rules = cls.nftables_rules_sort(
            raw_rules=rules,
            sort_config=config_hc['rules']['sort'],
        )

        return cls.nftables_rules_translate(
            raw_rules=rules,
            translate_config=config_hc['rules']['translate'],
        )

    @classmethod
    def nftables_unique_sequence(cls, raw_rules: list, sort_config: dict) -> bool:
        sequences = []

        for rule in raw_rules:
            _seq = cls._get_sequence(rule=rule, sort_config=sort_config)

            if _seq in sequences:
                return False

            sequences.append(_seq)

        return True

    @classmethod
    def nftables_rules_sort(cls, raw_rules: list, sort_config: dict) -> list:
        rules = []
        ordered = {}

        for rule in raw_rules:
            ordered[cls._get_sequence(rule=rule, sort_config=sort_config)] = rule

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
