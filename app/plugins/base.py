from abc import ABC, abstractmethod

class Plugin(ABC):

    name="plugin"

    @abstractmethod
    def run(self,target):
        pass

    def result(self,target,data,success=True,error=None):
        return {
            "tool":self.name,
            "target":target,
            "success":success,
            "count":len(data),
            "results":data,
            "error":error
        }
