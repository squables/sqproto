import sqprotolib as sqlib

class sqhandler:
    class method:
        def __init__(self, flag: sqlib.sqpacket.flag, callback):
            if(not isinstance(flag, sqlib.sqpacket.flag)): raise ValueError(f'flag must be type of {type(sqlib.sqpacket.flag).__name__}, not {type(flag).__name__}') 
            self.flag = flag
            self.callback = callback

    def __init__(self):
        self.methods = []

    def check_method_availability(self, flag: sqlib.sqpacket.flag):
        if(not isinstance(flag, sqlib.sqpacket.flag)): return False
        for m in self.methods:
            if(m.flag == flag): return False

        return True

    def check_method_name(self, method: method):
        if(not isinstance(method, self.method)): raise ValueError(f'method must be type of sqhandler, not {type(method).__name___}')
        for mtd in self.methods:
            if(mtd.callback.__name__ == method.callback.__name__): return mtd
        return None

    def register_method(self, method: method):
        if(not isinstance(method, self.method)): raise ValueError(f'method must be type of sqhandler, not {type(method).__name__}')
        if(not self.check_method_availability(method.flag)): raise ValueError(f'method flag must be available for use')

        mcheck = self.check_method_name(method)
        if(isinstance(mcheck, self.method)): raise ValueError(f'method name must be unique, {method.flag} already has method name {method.callback.__name__}')
        self.methods.append(method)
        print(f'binding {method.callback.__name__} to {method.flag.name}')

    def get_method(self, flag: sqlib.sqpacket.flag) -> method | None:
        if(not isinstance(flag, sqlib.sqpacket.flag)): raise ValueError(f'flag must be type of {type(sqlib.sqpacket.flag).__name__}, not {type(flag).__name__}')
        if(self.check_method_availability(flag)): return None
        
        for method in self.methods:
            if(method.flag ==  flag): return method
        
        return None
