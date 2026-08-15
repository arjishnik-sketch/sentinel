class CommandBuilder:

    def build(self, command, target):

        return (

            command

            .replace("TARGET", target)

            .replace("{{TARGET}}", target)

        )