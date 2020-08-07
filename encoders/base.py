
class EncoderMount(type):
    def __init__(cls, name, bases, attrs):
        if not hasattr(cls, 'encoders'):
            cls.encoders = []
        else:
            cls.register_encoders(cls)

    def register_encoders(cls, encoder):
        instance = encoder()
        cls.encoders.append(instance)


class Encoder(metaclass=EncoderMount):
    pass