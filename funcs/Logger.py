from time import time

class Logger:
    def __init__(self,filename:any):
        self.filename=filename
        
    def trace(self,message:str) -> None:
        print(f"{self.filename} - TRACE: {message}")
    
    def info(self,message:str) -> None:
        print(f"{self.filename} - INFO: {message}")
    
    def warn(self,message:str) -> None:
        print(f"{self.filename} - WARNING: {message}")
    
    def permission(self,message:str) -> None:
        print(f"{self.filename} - PERMISSION: {message}")
    
    def error(self,message:str) -> None:
        print(f"{self.filename} - ERROR: {message}")
    
    def time(self,func):
       def wrap(*args, **kwargs):
           start = time()
           result = func(*args,**kwargs)
           end = time()
           self.trace(f"{func.__name__}: {abs(end-start)}")
           return result
       return wrap