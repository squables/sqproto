import logger

class command_manager:
    class command():
        class cmd_res():
            def __init__(self, success: bool, message: str, data = None):
                self.success = success
                self.message = message
                self.data = data

            def strify(self): return f'{self.__class__.__name__}<success={self.success}, message={self.message}, data={self.data}>'
            def __str__(self): return self.strify()
            def __repr__(self): return self.strify()

        def __init__(self, trigger, name, cmd_help, callback): 
            self.trigger = trigger
            self.name = name
            self.cmd_help = cmd_help
            self.callback = callback

        def call(self, args):
            return self.callback(args)
    
    name = 'cmd_mgr'
    def __init__(self, prefix = None):
        self.commands = []
        self.prefix = prefix

    def reg_cmd(self, cmd: command) -> command.cmd_res:
        if(not isinstance(cmd, self.command)): return self.command.cmd_res(False, f'Command must be type of command_manager.command, not {type(cmd).__name__}')
        self.commands.append(cmd)

    def attempt_exec(self, args) -> tuple[bool, command.cmd_res]:
        if(len(args) == 0): return (False, self.command.cmd_res(True, None))
        trig = args[0]
        
        if(not trig.startswith(self.prefix)): return (False, self.command.cmd_res(True, None))
        for cmd in self.commands:
            if(self.prefix + cmd.trigger == trig): 
                logger.debug(f'executing {cmd.name}', self.name)
                res = cmd.call(args)
                if(not isinstance(res, self.command.cmd_res)): return (True, self.command.cmd_res(False, f'call didnt return correct result, returned {type(res).__name__}'))
                return (True, res)

        return (False, self.command.cmd_res(True, None))
