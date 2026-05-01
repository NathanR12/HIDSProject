import os  ##Allows os acess to the file
import time ## Uses time for a repeating loop
from watchdog.observers import Observer ##Watchdog observer for tracking
from watchdog.events import FileSystemEventHandler ##
import HashV
import YaraV
import PandasLog

 
## defining rules for the observer to follow. Setting the alert output.
class MonitorFolder(FileSystemEventHandler):
    FILE_SIZE= 100 * 1024 * 1024
    LOG_FILE = "HIDS_Log.txt" ##### Creating and defining the file where any alerts are stored.

    Suspicious_Types = {".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".scr", ".msi", ".reg", ".lnk"}

    ImportantPaths = { r"C:\Users\natro\Downloads", r"C:\Users\natro\Desktop", r"C:\Users\natro\Documents", r"C:\Users\natro\AppData\Roaming",  r"C:\Users\natro\AppData\Local\Temp", 
                      r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup", r"C:\Users\natro\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup", r"C:\Windows\System32\drivers\etc"}   ##### line dropped for visability
 
    def Log_To_File(self, message):
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        with open(self.LOG_FILE, "a", encoding="utf-8") as file:                   ### a = append mode, allowing it to add text to the file, \n changes the line
            file.write("[" + timestamp + "] " + message + "\n")

    def Is_Log_File(self, src_path):
        return os.path.abspath(src_path).lower() == os.path.abspath(self.LOG_FILE).lower()
   

    def on_created(self, event):
        if self.Is_Log_File(event.src_path):
            return
        self.Log_To_File(event.src_path + " " + event.event_type)
        self.checkFolderSize(event.src_path)
        self.checkSuspicious(event.src_path, "Created")


    def on_modified(self, event):
        if self.Is_Log_File(event.src_path):
            return
        self.Log_To_File(event.src_path + " " + event.event_type)
        self.checkFolderSize(event.src_path)
        self.checkSuspicious(event.src_path, "Modified")

    def on_deleted(self, event):
        if self.Is_Log_File(event.src_path):
            return
        self.Log_To_File(event.src_path + " " + event.event_type)

    def on_moved(self, event):
        if self.Is_Log_File(event.dest_path):
            return
        self.Log_To_File(event.src_path + " moved to " + event.dest_path)
        self.checkFolderSize(event.dest_path)
        self.checkSuspicious(event.dest_path, "Moved")
        

    def checkFolderSize(self, src_path):
        if not os.path.exists(src_path):
            self.Log_To_File("File no longer exists, cannot be checked" + src_path)
            return
        if os.path.isdir(src_path):
            return#
        try:
            file_size = os.path.getsize(src_path)

            if file_size > self.FILE_SIZE:
                file_size_mb = round(file_size / (1024 * 1024),2)
                self.Log_To_File("=======Large file detected=======")
                self.Log_To_File("File: " + src_path)
                self.Log_To_File("Size: " + str(file_size_mb) + " MB")
                self.Log_To_File("Reason: File is larger than the HIDS size limit")
                self.Log_To_File("=================================")

        except FileNotFoundError:
            self.Log_To_File("File disappeared before size check: " + src_path)
        except PermissionError:
            self.Log_To_File("No permission to check size: " + src_path)

    def checkSuspicious(self, src_path, event_type):
        if not os.path.exists(src_path):
            self.Log_To_File("File no longer exists, cannot check suspicious: " + src_path)                 #if file no longer exists return print
            return
        if os.path.isdir(src_path):
            return
        reasons = []

        file_name = os.path.basename(src_path)
        file_ext = os.path.splitext(src_path)[1].lower()                                            #seperates the file name from file type. 
        
       

        if file_ext in self.Suspicious_Types:                                                       ###checks for suspicous types as in Suspicious_Types
            reasons.append("Suspicious file type detected:" + file_ext)
        if reasons:
            self.Log_To_File("========== SUSPICIOUS CHANGE DETECTED ==========")
            self.Log_To_File("Event: " + event_type)
            self.Log_To_File("File: " + src_path)

            for reason in reasons:
                self.Log_To_File("Reason: " + reason)
            hash_results = HashV.Check_File_Hash(src_path)                                      #Calls the HashV.py file, specifically the Check_File_Hash function.
            for result in hash_results:                                                     #calls the result in HashV to log in watchdog
                self.Log_To_File(result) 
            
            
            yara_results = YaraV.Check_File_Yara(src_path)                                  ##calls yaraV####################################################################
            for result in yara_results:
                self.Log_To_File(result)  

            PandasLog.Log_Alert(
                alert_type="Suspicious File Change",
                source="Watchdog",
                event=event_type,
                file_path=src_path,
                reasons=reasons,
                hash_result=" | ".join(hash_results),
                yara_result=" | ".join(yara_results)
            )                                                    

            self.Log_To_File("==============================================")
        


## setting the observer to watch over certain folders and be callable to future files.
def start_monitor():   
        event_handler = MonitorFolder()
        observer = Observer()
        for path in MonitorFolder.ImportantPaths:
            if os.path.isdir(path):
                observer.schedule(event_handler, path, recursive=True)
                event_handler.Log_To_File("Monitoring " + path)
            else:
                event_handler.Log_To_File("Directory not found: " + path)

        observer.start()
        print ("Monitoring")  ## Notifying the user of 

        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            observer.stop()
            observer.join()

if __name__ =="__main__":
    start_monitor()

