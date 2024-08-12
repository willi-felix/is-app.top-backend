class Logger:
    def __init__(self,filename:any):
        self.filename=filename
    
    def info(self,message:str) -> None:
        print(f"{self.filename} - INFO: {message}")
    
    def warn(self,message:str) -> None:
        print(f"{self.filename} - WARNING: {message}")
    
    def error(self,message:str) -> None:
        print(f"{self.filename} - ERROR: {message}")
    
   