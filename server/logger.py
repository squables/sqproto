from colorist import ColorRGB

positive_c = ColorRGB(0, 255, 0)
negative_c = ColorRGB(255, 0, 0)
debug_c = ColorRGB(0, 255, 255)
neutral_c = ColorRGB(128, 128, 128)

def positive(message, extra = None, end='\n'):
    print(f'{neutral_c.OFF}[{positive_c}+{neutral_c}{f"({extra})" if extra is not None else ""}{neutral_c.OFF}] - {message}', end=end, flush=True)

def neutral(message, extra = None, end='\n'):
    print(f'{neutral_c.OFF}[{neutral_c}~{neutral_c}{f"({extra})" if extra is not None else ""}{neutral_c.OFF}] - {message}', end=end, flush=True)

def negative(message, extra = None, end='\n'):
    print(f'{neutral_c.OFF}[{negative_c}-{neutral_c}{f"({extra})" if extra is not None else ""}{neutral_c.OFF}] - {message}', end=end, flush=True)

def debug(message, extra = None, end='\n'):
    print(f'{neutral_c.OFF}[{debug_c}~{neutral_c}{f"({extra})" if extra is not None else ""}{neutral_c.OFF}] - {message}', end=end, flush=True)
