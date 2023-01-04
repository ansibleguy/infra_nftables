class FilterModule(object):

    def filters(self):
        return {
            "nftables_rules_translate": self.nftables_rules_translate,
            "nftables_rules_sort": self.nftables_rules_sort,
        }

    @staticmethod
    def nftables_rules_translate(raw_rules: list, cofnig: dict) -> list:
        rules = []

        return rules


    @staticmethod
    def nftables_rules_sort(raw_rules: list, config: dict) -> list:
       rules = []

       return rules
