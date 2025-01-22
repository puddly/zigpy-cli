import click
from zigpy.types import Channels


class HexOrDecIntParamType(click.ParamType):
    name = "integer"

    def convert(self, value, param, ctx):
        if isinstance(value, int):
            return value

        try:
            if value[:2].lower() == "0x":
                return int(value[2:], 16)
            else:
                return int(value, 10)
        except ValueError:
            self.fail(f"{value!r} is not a valid integer", param, ctx)


class ChannelsType(click.ParamType):
    name = "channels"

    def convert(self, value, param, ctx):
        if isinstance(value, Channels):
            return value

        try:
            return Channels.from_channel_list(map(int, value.split(",")))
        except ValueError:
            self.fail(f"{value!r} is not a valid channel list", param, ctx)


HEX_OR_DEC_INT = HexOrDecIntParamType()
CHANNELS_LIST = ChannelsType()
