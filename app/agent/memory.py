class AgentMemory:

    def __init__(self):

        self.history = []

    def remember(self, item):

        self.history.append(item)

    def latest(self, n=10):

        return self.history[-n:]

    def clear(self):

        self.history.clear()