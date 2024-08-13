import requests
import time
from .Logger import Logger

l = Logger("Translations.py")

class Translations:
    def __init__(self,api_key:str):
        self.api_key = api_key
        headers_ = {
            "Accept": "application/json",
            "Authorization":f"Bearer {self.api_key}",
            "X-GitHub-Api-Version":"2022-11-28"
        }
        response = requests.get("https://api.github.com/repos/ctih1/frii.site-frontend/contents/src/locales",headers=headers_)
        
        self.languages: dict = {}
        for file in response.json():
            filename = file["name"].split(".")[0]
            self.languages[filename] = requests.get(file["download_url"]).json()
        self.keys = {}
        self.percentages = self.__calculate_percentages__()
    
    def __calculate_percentages__(self,use_int:bool=False):
        main_language =  self.languages["en"]
        missing_keys:dict = {}
        total_keys = 0
        start:float = time.time()
        for key in main_language:
            total_keys+=1
            for language in self.languages:
                if key not in self.languages[language]:
                    if language not in missing_keys:
                        missing_keys[language] = {}
                        missing_keys[language]["misses"] = 0
                        missing_keys[language]["keys"] = []
                    missing_keys[language]["misses"] += 1
                    missing_keys[language]["keys"].append({"key":key,"ref":main_language.get(key)})
        print(f"Completed analysis in {float(time.time()-start)}s")
        percentages = {}
        for language in missing_keys:
            self.keys[language] = missing_keys[language]["keys"]
            result = 1-(missing_keys[language]["misses"]/total_keys)
            if(use_int): result = round(result*100)
            percentages[language] = result
        return percentages

    def get_percentages(self) -> dict:
        """Gets completion percentages of languages

        Returns:
            dict: {lang:0 to 1}
        """
        return self.percentages
    
    def get_keys(self,language:str) -> dict:
        return self.keys[language]