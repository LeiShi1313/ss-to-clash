
class RuleWriterMount(type):
    def __init__(cls, name, bases, attrs):
        if not hasattr(cls, 'rule_writers'):
            cls.rule_writers = {}
        else:
            cls.register_rule_writer(cls)

    def register_rule_writer(cls, rule_writer):
        instance = rule_writer()
        cls.rule_writers[instance.rule_name] = instance


class RuleWriter(metaclass=RuleWriterMount):
    pass