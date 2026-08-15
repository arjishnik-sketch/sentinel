class CommandRouter:

    def __init__(self):

        self.commands={}

    def register(self,name,handler):

        self.commands[name]=handler

    def execute(self,line):

        if not line.strip():

            return

        parts=line.split(maxsplit=1)

        cmd=parts[0]

        arg=parts[1] if len(parts)>1 else ""

        if cmd not in self.commands:

            print(f"Unknown command: {cmd}")

            return

        return self.commands[cmd](arg)

    def help(self):

        return sorted(self.commands.keys())
