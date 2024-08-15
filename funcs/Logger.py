from time import time
import aiohttp
import asyncio
import json

class Logger:
    def __init__(self,filename:any, webhook_url:str,trace_url:str):
        self.filename=filename
        self.webhook = webhook_url
        self.trace_url = trace_url 
    
    @staticmethod
    def __get_color(importance:str) -> int:
        default = 7912703
        values = {
            "warning":15232515,
            "permission":221928,
            "error":16724523,
            "critical":9505280
        } 
        return values.get(importance,default)
        
    async def __send_to_webhook(self,importance:str,message:str) -> None:
        try:
            if(importance in ["warning","permission","error","critical"]):
                url = self.webhook
            else:
                url = self.trace_url
            headers_ = {"Content-Type":"application/json"}
            body_ = {
                "embeds":[{
                        "title":importance.capitalize(),
                        "description":f"`{self.filename}` - {message}",
                        "color": self.__get_color(importance)
                }]
            }
            async with aiohttp.ClientSession() as session:
                await session.post(url,data=json.dumps(body_),headers=headers_)
        except Exception:
            pass
            
    def trace(self,message:str) -> None:
        print(f"{self.filename} - TRACE: {message}")
        asyncio.run(self.__send_to_webhook("trace",message))
    
    def info(self,message:str) -> None:
        print(f"{self.filename} - INFO: {message}")
        asyncio.run(self.__send_to_webhook("info",message))
    
    def warn(self,message:str) -> None:
        print(f"{self.filename} - WARNING: {message}")
        asyncio.run(self.__send_to_webhook("warning",message))
    
    def permission(self,message:str) -> None:
        print(f"{self.filename} - PERMISSION: {message}")
        asyncio.run(self.__send_to_webhook("permission",message))

    def error(self,message:str) -> None:
        print(f"{self.filename} - ERROR: {message}")
        asyncio.run(self.__send_to_webhook("error",message))

    def critical(self,message:str) -> None:
        print(f"{self.filename} - CRITICAL: {message}")
        asyncio.run(self.__send_to_webhook("critical",message))
        
    
    def time(self,func):
       def wrap(*args, **kwargs):
           start = time()
           result = func(*args,**kwargs)
           end = time()
           self.trace(f"{func.__name__}: {abs(end-start)}")
           return result
       return wrap