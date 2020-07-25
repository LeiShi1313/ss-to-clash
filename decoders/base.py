
class DecoderMount(type):
    def __init__(cls, name, bases, attrs):
        if not hasattr(cls, 'decoders'):
            cls.decoders = []
        else:
            cls.register_decoder(cls)

    def register_decoder(cls, decoder):
        instance = decoder()
        cls.decoders.append(instance)


class Decoder(metaclass=DecoderMount):
    pass