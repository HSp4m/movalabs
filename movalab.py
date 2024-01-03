from PyQt5 import QtCore, QtGui, QtWidgets
import yara
import sys
import qdarktheme
import os
import configparser
import requests
from virustotal_python import Virustotal
import hashlib
from datetime import datetime
from time import sleep, time
from rich.console import Console
import sqlite3
import getpass
from winotify import Notification, audio

console = Console()
hash = "";
historyPaths = []
historyDetections = []
historyFilesDetected = []
historyDetectionsPF = []
historyResult = []
config = configparser.ConfigParser()
current_dir = os.path.dirname(__file__)
settings_path = current_dir + "/settings/settings.ini"
quarantine_path = current_dir + "/settings/quarantine/"
meta_defender_api = "https://api.metadefender.com/v4/hash/"
QuickscanFolders = ["C:\\Windows\\Temp", f"C:\\Users\\{getpass.getuser()}\\AppData\\Local\\Temp", f"C:\\Users\\{getpass.getuser()}\\Downloads", f"C:\\Users\\{getpass.getuser()}\\Documents", "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup", "C:\\Windows\\System32", "C:\\Program Files", "C:\Program Files (x86)"]


def updater(module="dataset"):
    
    if module == "dataset":
        
        try:
            requestMd5 = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/hash/md5.txt");
            requestSha256 = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/hash/256.txt");
            requestSql = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/hash/HashDB");
            requestYara = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/new.yara");
            requestDataset = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/settings/dataset.ini");
            
        except:
            console.log(f"[red]Cannot make connection into github. Verify your internet connection and try again.")
            return False;

        if requestMd5.status_code == 200 and requestSha256.status_code == 200 and requestSql.status_code == 200 and requestYara.status_code == 200 and requestDataset.status_code == 200:
            
            contentMd5 = requestMd5.content;
            contentSha256 = requestSha256.content;
            contentSql = requestSql.content;
            contentYara = requestYara.content;
            contentDataset = requestDataset.content;
                
            fileMD5 = open(current_dir + "/hash/md5.txt", "wb");
            fileSha256 = open(current_dir + "/hash/256.txt", "wb");
            fileSql = open(current_dir + "/hash/HashDB", "wb");
            fileYara = open(current_dir + "/new.yara", "wb");
            fileDataset = open(current_dir + "/settings/dataset.ini", "wb");
                
            fileMD5.write(contentMd5)
            fileSha256.write(contentSha256)
            fileSql.write(contentSql)
            fileYara.write(contentYara)
            fileDataset.write(contentDataset)
                
                
            fileMD5.close();
            fileSha256.close();
            fileSql.close();
            fileYara.close();
            fileDataset.close();
                
            return True;


        else:
            console.log(f"[red]Cannot make connection into github. (404)")
            return False;
        
    elif module == "App":
        msg = QtWidgets.QMessageBox() 
        msg.setIcon(QtWidgets.QMessageBox.Warning) 
        msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.svg"))

        msg.setInformativeText(f"A app update is avaliable. Update Now?")
        msg.setText("Updater") 
                                        
                                        # setting Message box window title 
        msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel) 
                                        
                                        # start the app 
                                    
        retval = msg.exec_()
        
        if retval == 1024:
            try:
                requestApp = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/movalab.py");
                
            except:
                console.log(f"[red]Cannot make connection into github. Verify your internet connection and try again.")
                return False;

            if requestApp.status_code:
                
                
                    
                contentApp = requestApp.content;
                fileApp = open(__file__, "wb");
                fileApp.write(contentApp)
                fileApp.close();

                    
                return True;
                    
            else:
                console.log(f"[red]Cannot make connection into github. (404)")
                return False;
        
        else:
            return False;    
        
        
    elif module == "imgres":
        try:
            homeIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/SideBar/home-outlinedWHITE.svg").content
            quarantineIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/SideBar/quarantineWHITE.svg").content
            settingsIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/SideBar/settings_oWHITE.svg").content
            historyIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/SideBar/twotone-history.svg").content
            avIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/AntiVirus_ico.ico").content
            avSIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/AntiVirus_ico.svg").content
            avWhiteIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/AntiVirus_icoWhite.svg").content
            statusErrorIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/status-error-128.png").content
            statusInfoIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/status-info-128.png").content
            statusOkIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/status-ok-128.png").content
            statusWarningIcon = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/res/ico/status-warning-128.png").content
        
            homeIFile = open(current_dir + "/res/sidebar/home-outlinedWHITE.svg",'wb')
            quarantineIFile = open(current_dir + "/res/sidebar/quarantineWHITE.svg",'wb')
            settingsIFile = open(current_dir + "/res/sidebar/settings_oWHITE.svg",'wb')
            historyIFile = open(current_dir + "/res/sidebar/twotone-history.svg",'wb')
            avIFile = open(current_dir + "/res/ico/AntiVirus_ico.ico",'wb')
            avSIFile = open(current_dir + "/res/ico/AntiVirus_ico.svg",'wb')
            avWhiteIFile = open(current_dir + "/res/ico/AntiVirus_icoWhite.svg",'wb')
            statusErrorIFile = open(current_dir + "/res/ico/status-error-128.png",'wb')
            statusInfoIFile = open(current_dir + "/res/ico/status-info-128.png",'wb')
            statusOkIFile = open(current_dir + "/res/ico/status-ok-128.png",'wb')
            statusWarningIFile = open(current_dir + "/res/ico/status-warning-128.png",'wb')
            
            
            homeIFile.write(homeIcon)
            quarantineIFile.write(quarantineIcon)
            settingsIFile.write(settingsIcon)
            historyIFile.write(historyIcon)
            avIFile.write(avIcon)
            avSIFile.write(avSIcon)
            avWhiteIFile.write(avWhiteIcon)
            statusErrorIFile.write(statusErrorIcon)
            statusInfoIFile.write(statusInfoIcon)
            statusOkIFile.write(statusOkIcon)
            statusWarningIFile.write(statusWarningIcon)
            
            
            homeIFile.close()
            quarantineIFile.close()
            settingsIFile.close()
            historyIFile.close()
            avIFile.close()
            avSIFile.close()
            avWhiteIFile.close()
            statusErrorIFile.close()
            statusInfoIFile.close()
            statusOkIFile.close()
            statusWarningIFile.close()
            
            
        except requests.ConnectionError as e:
            console.log(f'[red]No internet connection. [white]{e}')
            
    elif module == 'settings':
        
        try:
            
            settingsIni = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/settings/settings.ini");
            
            settingsFile = open(current_dir + '/settings/settings.ini', 'wb')
            
            settingsFile.write(settingsIni.content)
            
            settingsFile.close()
            
        except requests.ConnectionError as e:
            console.log(f'[red]No internet connection. [white]{e}')
        
    
def compileHashes():
    global DatasetVersion__;
    global md5List;
    global sha256List;
    global rules;
    global db_cursor;
    global automaticUpdates;
    global scanHistory;
    global style;
    global virustotal;
    global vrapikey;
    global metadefenderkey;
    global metadefender;
    
    
    try:
        
        with open(current_dir + "\\hash\\md5.txt", "r") as hashFile:
            md5List = hashFile.read()
                
    except:
                
        console.log(f"[red]hash compile[white] Returned a unexpected error. Verify if the 'hash/md5.txt' file exist or open this app on powershell")
        sleep(1)
                
        exit();      
                                    
    try:
                
        with open(current_dir + "\\hash\\256.txt", "r") as hashF:
            sha256List = hashF.read()
                    
    except:
                
        console.log(f"[red]hash compile[white] Returned a unexpected error. Verify if the 'hash/256.txt' file exist or open this app on powershell")
        sleep(1)
                
        exit();      
        
    try:
        
        fh = open(current_dir + '\\new.yara')
        rules = yara.compile(file=fh)

        fh.close()
        
    except:
        
        console.log(f"[red]Yara compile[white] Returned a unexpected error. Verify if the 'new.yara' file exist or open this app on powershell")
        sleep(1)
        
        exit();
        
    try:
        db_file = "./hash/HashDB"
        
        hashes = sqlite3.connect(db_file)
        db_cursor = hashes.cursor()
        
    except:
        console.log(f"[red]Database connection[white] Returned a unexpected error. Verify if the 'hash' folder exist or open this app on powershell")
        exit();

    DatasetVersion__ = getDatasetVersion()

    try:
        
        config.read(settings_path)

        
        automaticUpdates = config["-settings-"]["automatic_update"]
        scanHistory = config["-settings-"]["scan_history"]
        style = config["-settings-"]["style"]
        virustotal = config["-settings-"]["virustotal"]
        vrapikey = config['-settings-']['vrapikey']
        metadefenderkey = config["-settings-"]["metadefenderkey"]
        metadefender = config["-settings-"]["metadefender"]

    except:
        
        console.log(f"[red]Settings compile[white] Returned a unexpected error. Verify if the 'settings' folder exist or open this app on powershell")
        sleep(1)
        
        exit();
    
def mode(status=None):
    global LatestVersion__;
    global AppVersion__;
    
    timeInitial__ = time();
    __NaN = 0
    __missing = 0
    
    
        
    try:

        __Page = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/settings/version.ini")
        LatestVersion__ = __Page.content.decode('utf-8')
        AppVersion__ = "1.3.6"
    
    except:
        
        console.log(f"[red]Fetch version[white] Returned a unexpected error. Check internet connection and try again.")
        exit()

       
    
    __updaterResult = update()
    __updaterDataResult = update("data")
    
        
    
    
    if __updaterDataResult == True:
        console.log(f"[red]Module Dataset[white] Missing update")
        console.log(f"[yellow]Starting update...")
        status.stop()
        __updaterResult__ = updater()
        
        if __updaterResult__ == True:
             
            
            console.log(f"[green]Dataset Update completed sucefully!") 
            compileHashes();
        
        else:
            console.log(f"[red]Dataset Update cannot be completed.")
            
            
        
    else:
        console.log(f"[green]Module Dataset[white] ok")
        
        
    if __updaterResult == True:
        console.log(f"[red]Module App[white] Missing update")
        console.log(f"[yellow]Starting update...")
        status.stop()
        __updaterResult__ = updater("App")
        
        if __updaterResult__ == True:
            
            console.log(f"[bold green]Update completed sucefully! [A restart is needed.]") 
            __missing +=1;
        else:
            console.log(f"[red]Update cannot be completed.")

    else:
        console.log(f"[green]Module App[white] ok")
        
            

    if os.path.isfile(current_dir + "\\new.yara") and os.path.isfile(current_dir + "/hash/256.txt") and os.path.isfile(current_dir + "/hash/HashDB") and os.path.isfile(current_dir + "/hash/md5.txt"):
            
        console.log(f"[green]Module Dataset.F[white] ok")
        
    else:
        console.log(f"[red]Module Dataset.F[white] missing")
        console.log("[bold yellow]Restauring..")
        __updaterResult__ = updater()
        
        if __updaterResult__ == True:
             
            
            console.log(f"[green]Dataset files restaured sucefully!") 
        
        else:
            console.log(f"[red]Dataset files cannot be restaured. Reinstall the app.")
            __missing += 1;
        
    if os.path.isfile(current_dir + '/res/sidebar/home-outlinedWhite.svg') and os.path.isfile(current_dir + '/res/sidebar/quarantineWHITE.svg') and os.path.isfile(current_dir + '/res/sidebar/settings_oWHITE.svg') and os.path.isfile(current_dir + '/res/sidebar/twotone-history.svg') and os.path.isfile(current_dir + '/res/ico/AntiVirus_ico.ico') and os.path.isfile(current_dir + '/res/ico/AntiVirus_ico.svg') and os.path.isfile(current_dir + '/res/ico/AntiVirus_icoWhite.svg') and os.path.isfile(current_dir + '/res/ico/status-error-128.png') and os.path.isfile(current_dir + '/res/ico/status-info-128.png') and os.path.isfile(current_dir + '/res/ico/status-ok-128.png') and os.path.isfile(current_dir + '/res/ico/status-warning-128.png'):
        console.log(f"[green]Module UI icons[white] ok")
        
            
    else:
        console.log(f"[red]Module UI icons[white] Not found/Missing files")
        console.log('[yellow]Restauring...')
        
        updater('imgres')
        
        console.log('[blue]A restart is need.')
        __missing+=1
        
           
    if os.path.isfile(settings_path):
        console.log(f"[green]Module Settings[white] ok")
        
        
    else:
        
        console.log(f"[red]Module Settings[white] Not found")
        console.log(f'[yellow]Restauring...')
        
        updater('settings')
        
        console.log('[blue]A restart is need.')
        __missing += 1
    
    
    
    compileHashes();
    
        
    
    if __missing == 0:
            timeFineshed__ = time();
            sleep(1)
            console.log(f"[green]App Loaded ({DatasetVersion__}) ({AppVersion__})! [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")
        
    else:
    
        sleep(1)
        console.log(f"[red]App cannot load. {__missing} errors ocurred")
        exit()
        


def verifyModules():
    with console.status("[bold green]Working on app load...") as status:
       mode(status)


def getMalwareType256(hash):
    with open(current_dir + "\\hash\\256.txt", "r") as hashF:
        for line in hashF:
                                    
            for hashes in line.split():
                splited = hashes.split(":")
                                        
                if splited[0] == hash:
                    threat = splited[1]
                                
                    return threat;
                                            

                                            
                else:
                    continue 


    

def quickScan(folders, self):
    __missing = 0;
    __founded = 0;
    __foundInFolder = 0;
    historyFilesDetected = []
    
    icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoWhite.svg') 
    tray = QtWidgets.QSystemTrayIcon() 
    tray.setIcon(icon) 
    tray.setVisible(True)                   
    tray.show()
    
    self.resultWidget.clear()
    
    if self.AutomaticUpdates.isChecked() == True:
        with console.status(f"[bold green]Verifying for updates...") as __None__:
            __updaterResult = update()
            __updaterDataResult = update("data")
            
            if __updaterResult == True:
                console.log(f"[yellow]Starting a App update!") 
                __None__.stop();
                __updaterResult__ = updater("App")
                if __updaterResult__ == True:
                    console.log(f"[green]Update completed sucefully! [A restart is needed.]") 
                    
                    
                else:
                    console.log(f"[red]Update cannot be completed.")
                    
            
            if __updaterDataResult == True:
                console.log(f"[yellow]Starting a Dataset update!") 
                __updaterResult__ = updater();
                
                if __updaterResult__ == True:
                    console.log(f"[green]Update completed sucefully!") 
                    compileHashes();
                    
                else:
                    console.log(f"[red]Update cannot be completed.")
                    
                
            console.log(f"[green]Scan will be started soon...")
            
        
    timeInitial__ = time();
    with console.status("[bold green] Quick scan in progress..."):
        notify(None,"status-info-128.png", "A quick scan will verify important parts of your system. Be patient","A quick scan has been started.")
        
        __totalFolders = len(folders);
        
        for folder in folders:
            __foundInFolder = 0;
            __totalFiles =sum(len(files) for _, _, files in os.walk(folder))
            console.log(f"Processing folder: '{folder}' itens: '{__totalFiles}'")
            
            for root, dirs, files in os.walk(folder):
                
                    
                    for file_name in files:
                        file = os.path.join(root, file_name)
                        fileR = file.replace("\\", "/")
                            
                        try:
                            
                            
                            with open(file,'rb') as filef:
                                
                                file_content = filef.read()
                                matchesFolder = rules.match(data=file_content)
                                
                            hashMD5 = hashlib.md5(file_content).hexdigest()
                            hashSha256 = hashlib.sha256(file_content).hexdigest()
                            
                            __InDB = db_cursor.execute(f"SELECT hash, name FROM HashDB WHERE hash = '{hashMD5}'").fetchone()
                            
                            if isinstance(__InDB, tuple) and file_name not in historyFilesDetected:
                                __foundInFolder += 1;
                                __founded += 1;
                                console.log(f"[red]'{file_name}'[white] is infected with [red]'{__InDB[1]}'")
                                historyFilesDetected.append(file_name)
                                self.resultWidget.insertItem(0,f"{file} ({__InDB[1]})")
                                self.Tabs.setCurrentIndex(3)
                                            

                            
                            if hashMD5 in md5List and file_name not in historyFilesDetected:
                                historyFilesDetected.append(file_name)
                                __founded += 1;
                                __foundInFolder += 1;
                                console.log(f"[red]'{file_name}'[white] is infected with [red]'Win.unknowMalware!UDS@BadHash.GEN'")
                                self.resultWidget.insertItem(0,f"{file} (Win.unknowMalware!UDS@BadHash.GEN)")
                                self.Tabs.setCurrentIndex(3)
                            
                            if hashSha256 in sha256List and file_name not in historyFilesDetected:
                                __founded += 1;
                                historyFilesDetected.append(file_name)
                                threat = getMalwareType256(hashSha256)
                                console.log(f"[red]'{file_name}'[white] is infected with [red]'{threat}'")
                                self.resultWidget.insertItem(0,f"{file} ({threat})")
                                self.Tabs.setCurrentIndex(3)
                            
                            if matchesFolder != [] and file_name not in historyFilesDetected:
                                __founded += 1;
                                __foundInFolder += 1;
                                for match in matchesFolder:
                                    historyFilesDetected.append(file_name)
                                    threat = match.meta.get('threat', "?")
                                    
                                    if threat == "?":
                                        threat = match.meta.get('malware_family', "?")
                                        if threat == "?":
                                            threat = "Win.unknowMalware!UDS.GEN"
                                            
                                    if threat.split(':')[0] == 'not-a-virus':
                                        threat = threat.replace('HEUR:','')
                                        threat = threat.split(':')[0] + ':HEUR:' + threat.replace('not-a-virus:','')
                                    else:
                                        threat = "HEUR:" + threat.replace('HEUR:','')
                                    
                                            
                                    console.log(f"[red]'{file_name}'[white] is infected with [red]'{threat}'")          
                                    self.resultWidget.insertItem(0,f"{file} ({threat})")
                                    self.Tabs.setCurrentIndex(3)
                                    
                        except:
                            
                            console.log(f"[red] '{file}' has been skipped (Permission denied)") 
            
            console.log(f"'{folder}' Has been processed. '{__foundInFolder}' malwares found")
                         
        if __founded == 0:
            timeFineshed__ = time();
            console.log(f"[bold green] No malwares found. [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")
            notify(None,"status-ok-128.png", "No malware detected in quick scan.","No malware detected")
        else:
            timeFineshed__ = time();
            console.log(f"[red]'{__founded}' malwares found. [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")    
            notify(None,"status-warning-128.png", f"{__founded} Malwares detected in quick scan. Open the app for more information.","Malwares detected")
def scaninfo(self):
    historyResult = []
    __get = 0
    item = self.historyListWidget.currentItem()
    
    current_item = str(item.text())
    
    __fDetections = current_item.split(", ")
    __fileDetections = __fDetections[1].split(" ")[0]
    console.log(f"[green][[white]+[green]][white] Scan fetch started.")
    with console.status(f"[bold green]Getting info of {__fileDetections} malwares...") as status:
        
        for y in historyDetections:
            __fileArray = y.split(": ")
            __fileArray = os.path.split(__fileArray[0])
            __filename = __fileArray[1].split(":")

            __filePath = __fileArray[0] + "/" + __filename[0]
        

            __fileThreat = y.split(": ")[1]
            
            
            for i in historyPaths:
                
                if i in current_item and i in __filePath and __filename[0] not in historyResult and i in historyPaths and __get < int(__fileDetections):
                    
                    historyResult.append(__filename[0])
                    console.log(f"[yellow]'{__filename[0]}'[white] detected as [yellow]'{__fileThreat}' ")
                    msg = QtWidgets.QMessageBox() 
                    msg.setIcon(QtWidgets.QMessageBox.Information)
                    msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.ico")) 
                    msg.setText(f"Scan ({__filename[0]})")
                    msg.setInformativeText(f"Detected: {__fileThreat} \nPath: {__filePath}") 
                    msg.setWindowTitle("Movalabs") 
                    msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                                
                                                # start the app 
                                            
                    retval = msg.exec_()
                    
                    
                    
                    __get += 1
                    
                else:
                    
                    continue
                
        
        
    
        
    if __get == 0:
        console.log(f"[yellow][?][white] Scan fetch ended.")
        pass
           
    
def scan_end(self,detections, scantype):
    data = datetime.now()
    current_time = data.strftime("%H:%M:%S")
    folder = scantype.split(": ")
    if detections == 0:
        self.historyListWidget.insertItem(0, f"{scantype} in {current_time}, {detections} detections")
        self.historyListWidget.item(0).setForeground(QtGui.QColor(255,255,255))
        
    elif detections == 1:
        self.historyListWidget.insertItem(0, f"{scantype} in {current_time}, {detections} detections")
        self.historyListWidget.item(0).setForeground(QtGui.QColor(255,172,0))
        
    else:
        self.historyListWidget.insertItem(0, f"{scantype} in {current_time}, {detections} detections")
        self.historyListWidget.item(0).setForeground(QtGui.QColor(191,0,1))
        
        #216, 56, 56
        #218,53,69

def notify(dir,image,description,title):

    
    notify = Notification(app_id="Movalabs", 
                     title=title,
                     msg=description,
                     duration="short",
                     icon=current_dir + '\\res\\ico\\' + image)
    notify.set_audio(audio.Default, loop=False)

    notify.show()

def list_files(dir, self, tray):

    self.progress.setVisible(True)
    
    historyFilesDetected = []
    total = 0;
    
    self.resultWidget.clear()
    
    __missing = 0;
    detected = 0;
    __totalFiles = 0;
    __filesVerificated = 0;
    
    if self.AutomaticUpdates.isChecked() == True:
        
        with console.status(f"[bold green]Verifying for updates...") as __None__:
            __updaterResult = update()
            __updaterDataResult = update("data")
            
            if __updaterResult == True:
                console.log(f"[yellow]Starting a App update!") 
                
                __None__.stop();
                __updaterResult__ = updater("App")
                if __updaterResult__ == True:
                    console.log(f"[green]Update completed sucefully! [A restart is needed.]") 
                    
                    
                else:
                    console.log(f"[red]Update cannot be completed.")
                    
            
            if __updaterDataResult == True:
                console.log(f"[yellow]Starting a Dataset update!") 
                __updaterResult__ = updater();
                
                if __updaterResult__ == True:
                    console.log(f"[green]Update completed sucefully!") 
                    compileHashes();
                    
                else:
                    console.log(f"[red]Update cannot be completed.")
                    
                
            console.log(f"[green]Scan will be started soon...")
                
                
            

    notify(dir, "status-info-128.png",f"A scan for the folder [{dir}] has been started. The scan mabe take a lot of time","A folder scan has been started.")
 
    __totalFiles =sum(len(files) for _, _, files in os.walk(dir))            
    self.progress.setMaximum(__totalFiles)
    
    
    console.log(f"[green][[white]+[green]][white] Starting Folder scan! [yellow]{__totalFiles}[white] files")

    with console.status(f"[bold green]Running a scan in '{dir}'...") as status:
        timeInitial__ = time();    
        for root, dirs, files in os.walk(dir):
    
            try:
                total += 1
                
                        
                fulltotal = total - 1
                
                for file_name in files:
                    

                    __filesVerificated += 1;
                    self.progress.setValue(__filesVerificated)
                    file = os.path.join(root, file_name)
                    fileR = file.replace("\\", "/")
                    if file_name not in ["movalab.py", "new.yara"]:
                        with open(file,'rb') as filef:
                                file_content = filef.read()
                                matchesFolder = rules.match(data=file_content)
                        
                        hashMD5 = hashlib.md5(file_content).hexdigest()
                        hashSha256 = hashlib.sha256(file_content).hexdigest()
                        
                        if hashSha256 in sha256List and file_name not in historyFilesDetected:
                            
                            historyDetections.insert(0,f"{fileR}: {threat}")
                            historyFilesDetected.append(file_name)
                            threat = getMalwareType256(hashSha256)
                            
                            console.log(f"[red]'{file_name}'[white] is infected with [red]'{threat}'")
                            
                            self.resultWidget.insertItem(fulltotal,f"{file_name} ({threat})")
                            self.Tabs.setCurrentIndex(3)

                        
                        __InDB = db_cursor.execute(f"SELECT hash, name FROM HashDB WHERE hash = '{hashMD5}'").fetchone()
                        
                        if isinstance(__InDB, tuple) and file_name not in historyFilesDetected:
                            
                            console.log(f"[red]'{file_name}'[white] is infected with [red]'{__InDB[1]}'")
                            historyFilesDetected.append(file_name)
                                        
                                        
                            self.resultWidget.insertItem(fulltotal,f"{file_name} ({__InDB[1]})")
                            self.Tabs.setCurrentIndex(3)
                                        
                            historyDetections.insert(0,f"{fileR}: {__InDB[1]}")
                        
                        if hashMD5 in md5List and file_name not in historyFilesDetected:
                            
                            historyFilesDetected.append(file_name)
                            historyDetections.insert(0,f"{fileR}: Win.unknowMalware!UDS@BadHash.GEN")
                            
                            console.log(f"[red]'{file_name}'[white] is infected with [red]'Win.unknowMalware!UDS@BadHash.GEN'")
                            
                            self.resultWidget.insertItem(fulltotal,f"{file_name} (Win.unknowMalware!UDS@BadHash.GEN)")
                            self.Tabs.setCurrentIndex(3)
                                        
                            

                                    
                        if matchesFolder != [] and file_name not in historyFilesDetected:
                            
                            
                            self.Tabs.setCurrentIndex(3)
                            for match in matchesFolder:

                                if file_name not in historyFilesDetected:    
                                    
                                    threat = match.meta.get('threat', "?")
                                        
                                    
                                    if threat == "?":
                                        threat = match.meta.get('malware_family', "?")
                                        if threat == "?":
                                            threat = "Win.unknowMalware!UDS.GEN"

                                    if threat.split(':')[0] == 'not-a-virus':
                                        threat = threat.replace('HEUR:','')
                                        threat = threat.split(':')[0] + ':HEUR:' + threat.replace('not-a-virus:','')
                                    else:
                                        threat = "HEUR:" + threat.replace('HEUR:','')

                                            
                                    historyFilesDetected.append(file_name)
                                    self.resultWidget.insertItem(fulltotal,f"{file_name} ({threat})")

                                    historyDetections.insert(0,f"{fileR}: {threat}")
                                    console.log(f"[red]'{file_name}'[white] is infected with [red]'{threat}'")
                    else:
                        continue 
        
            except:
                continue
    
    
    if len(historyFilesDetected) == 0:
        timeFineshed__ = time();
        self.progress.setVisible(False)
        historyDetectionsPF.append(f"{fileR}: {len(historyFilesDetected)}")
        scan_end(self, len(historyFilesDetected), f"Folder scan: {dir}")
        historyPaths.append(dir)
        
        notify(dir, "status-ok-128.png", f"The folder [{dir}] is safe!", "No malware found.")
        sleep(1)
        console.log(f"No malware found in '{dir}' [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")
                       
    else:
        timeFineshed__ = time();
        self.progress.setVisible(False)
        historyDetectionsPF.append(f"{fileR}: {len(historyFilesDetected)}")
        scan_end(self, len(historyFilesDetected), f"Folder scan: {dir}") 
        historyPaths.append(dir)
        
        notify(dir, "status-warning-128.png", f"{len(historyFilesDetected)} Malwares found in [{dir}]!", "Malware found.")
        sleep(1)
        console.log(f"[red]{len(historyFilesDetected)}[white] malwares found in [red]'{dir}' [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")
            
        
        
        
        
def itens(self):
    pass;
        

        
class Ui_Dialog(object):
    
    def setupUi(self, Dialog):
        
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(590, 300))
        MainWindow.setStyleSheet("")
      
        
        self.SideBar = QtWidgets.QLabel(MainWindow)
        self.SideBar.setGeometry(QtCore.QRect(-10, 0, 590, 300))
        #81, 89, 97
        #-10, 45, 61, 271
        self.SideBar.setStyleSheet("background-color: rgb(22,22,22);")
        #black
        self.SideBar.setText("")
        self.SideBar.setObjectName("SideBar")
        self.opacity_effect = QtWidgets.QGraphicsOpacityEffect() 
        self.opacity_effect.setOpacity(0.5) 
        self.SideBar.setGraphicsEffect(self.opacity_effect) 
        self.HomeTabButton = QtWidgets.QPushButton(MainWindow)
        #25
        self.HomeTabButton.setGeometry(QtCore.QRect(0, 25, 51, 31))
        font = QtGui.QFont()
        font.setPointSize(15)
        self.HomeTabButton.setFont(font)
        self.HomeTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
f"image: url(res/SideBar/home-outlinedWHITE.svg);\n"
"")
        self.HomeTabButton.setText("")
        self.HomeTabButton.setFlat(True)
        self.HomeTabButton.setObjectName("HomeTabButton")
        self.HistoryTabButton = QtWidgets.QPushButton(MainWindow)
        self.HistoryTabButton.setGeometry(QtCore.QRect(0, 185, 51, 31))
        #90
        font = QtGui.QFont()
        font.setPointSize(15)
        self.HistoryTabButton.setFont(font)
        self.HistoryTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
f"image: url(res/SideBar/twotone-history.svg);")
        self.HistoryTabButton.setText("")
        self.HistoryTabButton.setFlat(True)
        self.HistoryTabButton.setObjectName("HistoryTabButton")
        self.SettingsTabButton = QtWidgets.QPushButton(MainWindow)
        self.SettingsTabButton.setGeometry(QtCore.QRect(0, 250, 51, 31))
        #90
        font = QtGui.QFont()
        font.setPointSize(15)
        self.SettingsTabButton.setFont(font)
        self.SettingsTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
f"image: url(res/SideBar/settings_oWHITE.svg);")
        self.SettingsTabButton.setText("")
        self.SettingsTabButton.setFlat(True)
        self.SettingsTabButton.setObjectName("SettingsTabButton")
        self.QuarantineTabButton = QtWidgets.QPushButton(MainWindow)
        self.QuarantineTabButton.setGeometry(QtCore.QRect(0, 120, 51, 31))
        #130
        font = QtGui.QFont()
        font.setPointSize(15)
        self.QuarantineTabButton.setFont(font)
        self.QuarantineTabButton.setStyleSheet("background-color: qradialgradient(spread:pad, cx:0.5, cy:0.5, radius:0.5, fx:0.1468, fy:0.1468, stop:1 rgba(0, 0, 0, 0));\n"
f"image: url(res/SideBar/quarantineWHITE.svg);")
        
        self.QuarantineTabButton.setText("")
        self.QuarantineTabButton.setFlat(True)
        self.QuarantineTabButton.setObjectName("QuarantineTabButton")
        
        self.Tabs = QtWidgets.QStackedWidget(MainWindow)
        self.Tabs.setGeometry(QtCore.QRect(50, 0, 591, 301))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.Tabs.setFont(font)
        self.Tabs.setStyleSheet("")
        self.Tabs.setObjectName("Tabs")
        self.HomeTab = QtWidgets.QWidget()
        self.HomeTab.setObjectName("HomeTab")
        self.HomeTitle = QtWidgets.QLabel(self.HomeTab)
        self.HomeTitle.setGeometry(QtCore.QRect(-40, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.HomeTitle.setFont(font)
        self.HomeTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.HomeTitle.setObjectName("HomeTitle")
        self.SelectFileButton = QtWidgets.QPushButton(self.HomeTab)
        #5, 45, 121, 31
        #240, 250, 121, 31
        self.SelectFileButton.setGeometry(QtCore.QRect(100, 100, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.SelectFileButton.setFont(font)
        self.SelectFileButton.setFlat(False)
        self.SelectFileButton.setObjectName("SelectFileButton")
        
        self.SelectFolderButton = QtWidgets.QPushButton(self.HomeTab)
        self.SelectFolderButton.setGeometry(QtCore.QRect(260, 100, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.SelectFolderButton.setFont(font)
        self.SelectFolderButton.setFlat(False)
        self.SelectFolderButton.setObjectName("SelectFolderButton")
        
        self.QuickScanButton = QtWidgets.QPushButton(self.HomeTab)
        self.QuickScanButton.setGeometry(QtCore.QRect(180, 150, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.QuickScanButton.setFont(font)
        self.QuickScanButton.setFlat(False)
        self.QuickScanButton.setObjectName("QuickScanButton")
        
        self.Tabs.addWidget(self.HomeTab)
        self.SettingsTab = QtWidgets.QWidget()
        self.SettingsTab.setObjectName("SettingsTab")
        self.SettingsTitle = QtWidgets.QLabel(self.SettingsTab)
        self.SettingsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.SettingsTitle.setFont(font)
        self.SettingsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.SettingsTitle.setObjectName("SettingsTitle")
        self.UseVirusTotalApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseVirusTotalApiCheckBox.setGeometry(QtCore.QRect(5, 45, 451, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.UseVirusTotalApiCheckBox.setFont(font)
        self.UseVirusTotalApiCheckBox.setObjectName("UseVirusTotalApiCheckBox")
        self.AutomaticUpdates = QtWidgets.QCheckBox(self.SettingsTab)
        self.AutomaticUpdates.setGeometry(QtCore.QRect(5, 185, 451, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.AutomaticUpdates.setFont(font)
        self.AutomaticUpdates.setObjectName("AutomaticUpdates")
        self.EnableScanHistory = QtWidgets.QCheckBox(self.SettingsTab)
        self.EnableScanHistory.setGeometry(QtCore.QRect(5, 205, 451, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.EnableScanHistory.setFont(font)
        self.EnableScanHistory.setObjectName("EnableScanHistory")
        
        self.MalwareBazzarApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.MalwareBazzarApiCheckBox.setGeometry(QtCore.QRect(5, 135, 451, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.MalwareBazzarApiCheckBox.setFont(font)
        self.MalwareBazzarApiCheckBox.setObjectName("MalwareBazzarApiCheckBox")
        
        self.MalwareBazzarApi = QtWidgets.QLineEdit(self.SettingsTab)
        self.MalwareBazzarApi.setGeometry(QtCore.QRect(5, 155, 391, 20))
        font = QtGui.QFont()
        font.setPointSize(7)
        self.MalwareBazzarApi.setFont(font)
        self.MalwareBazzarApi.setStyleSheet("")
        self.MalwareBazzarApi.setInputMask("")
        self.MalwareBazzarApi.setText("")
        self.MalwareBazzarApi.setMaxLength(32767)
        self.MalwareBazzarApi.setFrame(False)
        self.MalwareBazzarApi.setEchoMode(QtWidgets.QLineEdit.Password)
        self.MalwareBazzarApi.setAlignment(QtCore.Qt.AlignCenter)
        self.MalwareBazzarApi.setObjectName("MalwareBazzarApi")
        
        self.VirusTotalApiKey = QtWidgets.QLineEdit(self.SettingsTab)
        self.VirusTotalApiKey.setGeometry(QtCore.QRect(5, 65, 391, 20))
        font = QtGui.QFont()
        font.setPointSize(7)
        self.VirusTotalApiKey.setFont(font)
        self.VirusTotalApiKey.setStyleSheet("")
        self.VirusTotalApiKey.setInputMask("")
        self.VirusTotalApiKey.setText("")
        self.VirusTotalApiKey.setMaxLength(32767)
        self.VirusTotalApiKey.setFrame(False)
        self.VirusTotalApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.VirusTotalApiKey.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusTotalApiKey.setObjectName("VirusTotalApiKey")
        
        self.SaveSettingsButton = QtWidgets.QPushButton(self.SettingsTab)
        self.SaveSettingsButton.setGeometry(QtCore.QRect(415, 265, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.SaveSettingsButton.setFont(font)
        self.SaveSettingsButton.setFlat(False)
        self.SaveSettingsButton.setObjectName("SaveSettingsButton")
        self.UseMetaDefenderApiCheckBox = QtWidgets.QCheckBox(self.SettingsTab)
        self.UseMetaDefenderApiCheckBox.setGeometry(QtCore.QRect(5, 90, 481, 17))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.UseMetaDefenderApiCheckBox.setFont(font)
        self.UseMetaDefenderApiCheckBox.setObjectName("UseMetaDefenderApiCheckBox")
        self.MetaDefenderApiKey = QtWidgets.QLineEdit(self.SettingsTab)
        self.MetaDefenderApiKey.setGeometry(QtCore.QRect(5, 110, 391, 20))
        self.MetaDefenderApiKey.setStyleSheet("")
        self.MetaDefenderApiKey.setInputMask("")
        self.MetaDefenderApiKey.setText("")
        self.MetaDefenderApiKey.setMaxLength(32767)
        self.MetaDefenderApiKey.setFrame(False)
        self.MetaDefenderApiKey.setEchoMode(QtWidgets.QLineEdit.Password)
        self.MetaDefenderApiKey.setAlignment(QtCore.Qt.AlignCenter)
        self.MetaDefenderApiKey.setObjectName("MetaDefenderApiKey")
        self.VerifyUpdatesButton = QtWidgets.QPushButton(self.SettingsTab)
        self.VerifyUpdatesButton.setGeometry(QtCore.QRect(260, 265, 150, 31))
        font = QtGui.QFont()
        font.setPointSize(11)
        self.VerifyUpdatesButton.setFont(font)
        self.VerifyUpdatesButton.setFlat(False)
        self.VerifyUpdatesButton.setObjectName("VerifyUpdatesButton")
        self.LightModeButton = QtWidgets.QPushButton(self.SettingsTab)
        self.LightModeButton.setGeometry(QtCore.QRect(135, 265, 121, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.LightModeButton.setFont(font)
        self.LightModeButton.setFlat(False)
        self.LightModeButton.setObjectName("LightModeButton")
        self.Tabs.addWidget(self.SettingsTab)
        self.VirusScanResults_hidden = QtWidgets.QWidget()
        self.VirusScanResults_hidden.setObjectName("VirusScanResults_hidden")
        self.VirusResultsTitle = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.VirusResultsTitle.setGeometry(QtCore.QRect(0, 0, 551, 41))
        font = QtGui.QFont()
        font.setPointSize(23)
        self.VirusResultsTitle.setFont(font)
        self.VirusResultsTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.VirusResultsTitle.setObjectName("VirusResultsTitle")
        self.FileName = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileName.setGeometry(QtCore.QRect(5, 45, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FileName.setFont(font)
        self.FileName.setObjectName("FileName")
        self.FilePath = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FilePath.setGeometry(QtCore.QRect(5, 75, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FilePath.setFont(font)
        self.FilePath.setObjectName("FilePath")
        self.FileHash = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.FileHash.setGeometry(QtCore.QRect(5, 110, 541, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.FileHash.setFont(font)
        self.FileHash.setObjectName("FileHash")
        self.label = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.label.setGeometry(QtCore.QRect(193, 155, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.IsFileVirusY_N = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.IsFileVirusY_N.setGeometry(QtCore.QRect(140, 160, 181, 71))
        #5, 190, 101, 31
        font = QtGui.QFont()
        font.setPointSize(18)
        font.setBold(True)
        font.setWeight(75)
        self.IsFileVirusY_N.setFont(font)
        self.IsFileVirusY_N.setStyleSheet("color: rgb(255, 0, 0);")
        self.IsFileVirusY_N.setAlignment(QtCore.Qt.AlignCenter)
        self.IsFileVirusY_N.setObjectName("IsFileVirusY_N")
        self.ReturnToHomeTabButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.ReturnToHomeTabButton.setGeometry(QtCore.QRect(5, 265, 91, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.ReturnToHomeTabButton.setFont(font)
        self.ReturnToHomeTabButton.setDefault(False)
        self.ReturnToHomeTabButton.setFlat(False)
        self.ReturnToHomeTabButton.setObjectName("ReturnToHomeTabButton")
        self.QuarentineFileButton = QtWidgets.QPushButton(self.VirusScanResults_hidden)
        self.QuarentineFileButton.setGeometry(QtCore.QRect(100, 265, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.QuarentineFileButton.setFont(font)
        self.QuarentineFileButton.setDefault(False)
        self.QuarentineFileButton.setFlat(False)
        self.QuarentineFileButton.setObjectName("QuarentineFileButton")
        self.line = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.line.setGeometry(QtCore.QRect(0, 150, 540, 5))
        self.line.setStyleSheet("background-color: rgb(74, 74, 74);")
        self.line.setText("")
        self.line.setIndent(-1)
        self.line.setObjectName("line")
        self.VirusTotalWidget = QtWidgets.QWidget(self.VirusScanResults_hidden)
        self.VirusTotalWidget.setGeometry(QtCore.QRect(5, 160, 190, 50))
        self.VirusTotalWidget.setObjectName("VirusTotalWidget")
        self.label_3 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_3.setGeometry(QtCore.QRect(5, 4, 161, 21))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_3.setObjectName("label_3")
        self.DetectionsText = QtWidgets.QLabel(self.VirusTotalWidget)
        self.DetectionsText.setGeometry(QtCore.QRect(54, 25, 161, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.DetectionsText.setFont(font)
        #self.DetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.DetectionsText.setObjectName("DetectionsText")
        self.label_5 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_5.setGeometry(QtCore.QRect(10, 47, 161, 16))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_5.setFont(font)
        self.label_5.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_5.setObjectName("label_5")
        self.label_3.raise_()
        self.label_5.raise_()
        self.DetectionsText.raise_()
        self.MetaDefenderWidget = QtWidgets.QWidget(self.VirusScanResults_hidden)
        self.MetaDefenderWidget.setGeometry(QtCore.QRect(310, 160, 221, 71))
        self.MetaDefenderWidget.setObjectName("MetaDefenderWidget")
        self.label_4 = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.label_4.setGeometry(QtCore.QRect(10, 9, 201, 21))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_4.setFont(font)
        self.label_4.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_4.setObjectName("label_4")
        self.MetaDefenderDetectionsText = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.MetaDefenderDetectionsText.setGeometry(QtCore.QRect(10, 20, 201, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.MetaDefenderDetectionsText.setFont(font)
        self.MetaDefenderDetectionsText.setAlignment(QtCore.Qt.AlignCenter)
        self.MetaDefenderDetectionsText.setObjectName("MetaDefenderDetectionsText")
        self.label_6 = QtWidgets.QLabel(self.MetaDefenderWidget)
        self.label_6.setGeometry(QtCore.QRect(10, 47, 201, 21))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.label_6.setFont(font)
        self.label_6.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_6.setObjectName("label_6")
        self.label_4.raise_()
        self.label_6.raise_()
        self.MetaDefenderDetectionsText.raise_()
        self.Tabs.addWidget(self.VirusScanResults_hidden)
        self.FolderScanResults = QtWidgets.QWidget()
        resultLayout = QtWidgets.QGridLayout(self.FolderScanResults)
        self.resultWidget = QtWidgets.QListWidget(self.FolderScanResults)
        resultLayout.addWidget(self.resultWidget)
        self.Tabs.addWidget(self.FolderScanResults)
        
        
        
        self.SideBar_2 = QtWidgets.QLabel(MainWindow)
        self.SideBar_2.setGeometry(QtCore.QRect(-10, -10, 71, 51))
        self.SideBar_2.setText("")
        self.SideBar_2.setObjectName("SideBar_2")
        
        
        
        self.CurrentTabHome = QtWidgets.QLabel(MainWindow)
        self.CurrentTabHome.setGeometry(QtCore.QRect(0, 25, 3, 31))
        self.CurrentTabHome.setText("")
        self.CurrentTabHome.setObjectName("CurrentTabHome")
        
        self.CurrentTabSettings = QtWidgets.QLabel(MainWindow)
        self.CurrentTabSettings.setGeometry(QtCore.QRect(0, 250, 3, 31))
        #90
        self.CurrentTabSettings.setText("")
        self.CurrentTabSettings.setObjectName("CurrentTabSettings")
        
        self.CurrentTabQuarantine = QtWidgets.QLabel(MainWindow)
        self.CurrentTabQuarantine.setGeometry(QtCore.QRect(0, 120, 3, 31))
        #130
        self.CurrentTabQuarantine.setText("")
        self.CurrentTabQuarantine.setObjectName("CurrentTabQuarantine")
        
        self.CurrentTabHistory = QtWidgets.QLabel(MainWindow)
        self.CurrentTabHistory.setGeometry(QtCore.QRect(0, 185, 3, 31))
        #130
        self.CurrentTabHistory.setText("")
        self.CurrentTabHistory.setObjectName("CurrentTabHistory")
        
        self.QuarantineTab = QtWidgets.QWidget()
        self.QuarantineTab.setObjectName("QuarantineTab")
        
       
        
        
        layout = QtWidgets.QGridLayout(self.QuarantineTab)
        self.listwidget = QtWidgets.QListWidget(self.QuarantineTab)
        count = 0
        current_item = None
        itens(self)
        
        self.QuarantineTitle = QtWidgets.QLabel(self.QuarantineTab)
        self.QuarantineTitle.setGeometry(QtCore.QRect(0, 0, 530, 45))
        font = QtGui.QFont()
        font.setPointSize(16)
        self.QuarantineTitle.setFont(font)
        self.QuarantineTitle.setAlignment(QtCore.Qt.AlignCenter)
        self.QuarantineTitle.setObjectName("QuarantineTitle")

        layout.addWidget(self.listwidget)
        
        self.RemoveFileButton = QtWidgets.QPushButton(self.QuarantineTab)
        self.RemoveFileButton.setGeometry(QtCore.QRect(400, 250, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(10)
        self.RemoveFileButton.setFont(font)
        self.RemoveFileButton.setDefault(False)
        self.RemoveFileButton.setFlat(False)
        self.RemoveFileButton.setObjectName("RemoveFileButton")
        
        self.Tabs.addWidget(self.QuarantineTab)
        
        self.HistoryTab = QtWidgets.QWidget()
        self.HistoryTab.setObjectName("HistoryTab")
        
        historyLayout = QtWidgets.QGridLayout(self.HistoryTab)
        self.historyListWidget = QtWidgets.QListWidget(self.HistoryTab)
        
        
        self.progress = QtWidgets.QProgressBar(self.HomeTab)
        self.progress.setGeometry(101, 150, 300, 25)
        self.progress.setMaximum(100)
        self.progress.setVisible(False)
        
        historyLayout.addWidget(self.historyListWidget)
        
        self.Tabs.addWidget(self.HistoryTab)
        
        self.Tabs.setCurrentIndex(0)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        
        
        
        def listitem(self):
            ''''''
            
            item = self.listwidget.currentItem()
            current_item = str(item.text())
            msg = QtWidgets.QMessageBox() 
            msg.setIcon(QtWidgets.QMessageBox.Warning) 
            msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\antiVirus_ico.svg"))
                                    
                                        # setting message for Message Box 
            msg.setText(f"{current_item}") 
            msg.setInformativeText("Threat: <Unknow>\n\nDecrypt file?")
                                        
                                        # setting Message box window title 
            msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
            msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.No) 
                                        
                                        # start the app 
                                    
            retval = msg.exec_()
            
            if retval == 1024:
                decryptFile(current_item)
            
            else:
                pass

        def browseFiles(MainWindow, self):
            historyFilesDetected = []
            icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoWhite.svg') 
    
        # Adding item on the menu bar 
            tray = QtWidgets.QSystemTrayIcon() 
            tray.setIcon(icon) 
            tray.setVisible(True) 
            
            
            tray.show()
            
            vrapikey = config["-settings-"]["vrapikey"]
            found = False;

            filepath_raw, filename_raw = os.path.split(str(QtWidgets.QFileDialog.getOpenFileName(MainWindow,
                                                                            "Select File",
                                                                            "YOUR-FILE-PATH")))
            
            filepath_raw = filepath_raw.replace("('", "")
            filename = filename_raw.replace("', 'All Files (*)')", "")


            self.FileName.setText("File Name: " + filename)

            filepath = (filepath_raw + "/" + filename)
            
            if self.AutomaticUpdates.isChecked() == True:
        
                with console.status(f"[bold green]Verifying for updates...") as __None__:
                    __updaterResult = update()
                    __updaterDataResult = update("data")
                    
                    if __updaterResult == True:
                        console.log(f"[yellow]Starting a App update!") 
                        
                        __None__.stop();
                        __updaterResult__ = updater("App")
                        if __updaterResult__ == True:
                            console.log(f"[green]Update completed sucefully! [A restart is needed.]") 
                            
                            
                        else:
                            console.log(f"[red]Update cannot be completed.")
                            
                    
                    if __updaterDataResult == True:
                        console.log(f"[yellow]Starting a Dataset update!") 
                        __updaterResult__ = updater();
                        
                        if __updaterResult__ == True:
                            console.log(f"[green]Update completed sucefully!") 
                            compileHashes();
                            
                        else:
                            console.log(f"[red]Update cannot be completed.")
                            
                        
                    console.log(f"[green]Scan will be started soon...")
            
            if os.path.isfile(filepath) and filename not in ["movalab.py", "new.yara"]:
                timeInitial__ = time();
                console.log(f"[green][[white]+[green]][white] Starting file scan!")
                with console.status(f"[bold green]Running a scan for the file '{filename}' ...") as status:
                    vrapikey = config['-settings-']['vrapikey']
                    direc = filepath
                    
                    file = open(filepath, "rb")
                    file_content = file.read()
                    suspecious = False;
                    found = False;
                    with open(direc,'rb') as filef:
                        
                        matches = rules.match(data=filef.read())
                        
                    
                    if matches != []:
                        
                        
                        
                        for match in matches:
                                if found != True:
                                    found = True;
                                    
                                    threat = match.meta.get('threat', '?')
                                    
                                    if threat == "?":
                                        threat = match.meta.get('malware_family', "?")
                                        
                                        if threat == "?": 
                                            threat = "Win.unknowMalware!UDS.GEN"
                                            
                                    if threat.split(':')[0] == 'not-a-virus':
                                        threat = threat.replace('HEUR:','')
                                        threat = threat.split(':')[0] + ':HEUR:' + threat.replace('not-a-virus:','')
                                    else:
                                        threat = "HEUR:" + threat.replace('HEUR:','')
                                    
                                    console.log(F"[red]'{filename}'[white] is infected with [red]'{threat}'")
                                    scan_end(self, 1, f"File scan: {filepath}")
                                    notify(filepath,"status-warning-128.png",f"Type: {threat} \nDetection: Yara rules","Malware Detected")
                                    self.FilePath.setText(f"Detection Type: Yara Rules ({threat})")
                                    
                                    
                    
                        
                    hashMD5 = hashlib.md5(file_content).hexdigest()
                    hashSha256 = hashlib.sha256(file_content).hexdigest()
                    file.close()    
                        
                    if hashSha256 in sha256List and found != True:
                            found = True;
                            threat = getMalwareType256(hashSha256)
                            console.log(f"[red]'{filename}'[white] is infected with [red]'{threat}'")
                            scan_end(self, 1, f"File scan: {filepath}")
                            notify(filepath,"status-warning-128.png",f"Type: {threat} \nDetection: Hash list","Malware Detected")
                            self.FilePath.setText("Detection Type: Hash List")
                                        

                        
                    __InDB = db_cursor.execute(f"SELECT hash, name FROM HashDB WHERE hash = '{hashMD5}'").fetchone()
                        
                    if isinstance(__InDB, tuple) and found != True:
                        
                        found = True;
                        self.FilePath.setText("Detection Type: Hash List")    
                        console.log(f"[red]'{filename}'[white] is infected with [red]'{__InDB[1]}'")
                        scan_end(self, 1, f"File scan: {filepath}")
                        notify(filepath,"status-warning-128.png",f"Type: {__InDB[1]} \nDetection: Hash list","Malware Detected")
                    
                    
                    if hashMD5 in md5List and found != True:
                            found = True;
                            console.log(f"[red]'{filename}'[white] is infected with [red]'Win.unknowMalware!UDS@BadHash.GEN'")
                            notify(filepath,"status-warning-128.png",f"Type: Win.unknowMalware!UDS@BadHash.GEN \nDetection: Hash list","Malware Detected")
                            self.FilePath.setText("Detection Type: Hash List")
                            scan_end(self, 1, f"File scan: {filepath}")
                    
                    
                                
                    
                    detections = 0;
                    
                    try:
                        if self.UseVirusTotalApiCheckBox.isChecked() and found != True and os.path.getsize(filepath) < 32000000:
                            if vrapikey != '':
                                if direc != '':
                                    if os.path.isfile(direc):
                                        found = False;
                                        
                                        
                                        files = {"file": (os.path.basename(filepath), open(os.path.abspath(filepath), "rb"))}
                                        
                                        vtotal = Virustotal(API_KEY=vrapikey)
                                        resp = vtotal.request("files", files=files, method="POST")
                                        id = resp.data["id"]
                                        headers = {"x-apikey": vrapikey}
                                        analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
                                        analysis_json = analysis.json()
                                        
                                        detections = analysis_json["data"]["attributes"]["stats"]["malicious"]
                                        not_detections = analysis_json["data"]["attributes"]["stats"]["undetected"]
                                        
                                        for _av in analysis_json["data"]["attributes"]["results"]:
                                            _result = analysis_json["data"]["attributes"]["results"][_av]["result"]
                                            
                                            if _result in ["null", None]:
                                                continue
                                            
                                            else:
                                                threat = _result
                                                engine = _av
                                                break;
                                        console.log(f"[blue]d: {detections} | n: {not_detections}")
                                        if not_detections == 0:
                                            self.DetectionsText.setStyleSheet("color: white")
                                            self.DetectionsText.setText(f"ERROR")
                                            found = False;
                                            
                                        elif detections > 4:
                                            scan_end(self, 1, f"File scan: {filepath}")
                                            console.log(F"[red]'{filename}'[white] is infected with [red]'{threat}'")
                                            
                                            notify(filepath,"status-warning-128.png",f"Type: {threat}\nDetection: VirusTotal \nEngine: {engine}","Malware Detected")
                                            self.FilePath.setText(f"Engine: {engine} ({threat})")
                                            self.DetectionsText.setStyleSheet("color: red")
                                            self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                                            found = True;

                                        else:
                                            
                                            found = False;
                                            self.DetectionsText.setStyleSheet("color: white")
                                            
                                            self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                                        console.log(f"[blue]Scan end")
                                    else:
                                        msg = QtWidgets.QMessageBox() 
                                        msg.setIcon(QtWidgets.QMessageBox.Critical) 
                                            
                                                # setting message for Message Box 
                                        msg.setText("Invalid File path") 
                                                
                                                # setting Message box window title 
                                        msg.setWindowTitle("ERROR") 
                                                
                                                # declaring buttons on Message Box 
                                        msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                                
                                                # start the app 
                                            
                                        retval = msg.exec_()
                                else:
                                    msg = QtWidgets.QMessageBox() 
                                    msg.setIcon(QtWidgets.QMessageBox.Critical) 
                                            
                                                # setting message for Message Box 
                                    msg.setText("No file set") 
                                                
                                                # setting Message box window title 
                                    msg.setWindowTitle("ERROR") 
                                                
                                                # declaring buttons on Message Box 
                                    msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                                
                                                # start the app 
                                            
                                    retval = msg.exec_()
                                
                            else:
                                msg = QtWidgets.QMessageBox() 
                                msg.setIcon(QtWidgets.QMessageBox.Critical) 
                                    
                                        # setting message for Message Box 
                                msg.setText("Virustotal Api.")
                                msg.setInformativeText(f"Virustotal apikey not set.") 
                                        
                                        # setting Message box window title 
                                msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
                                msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                        
                                        # start the app 
                                    
                                retval = msg.exec_()
                        else:
                            
                            self.DetectionsText.setStyleSheet("color: white")
                            self.DetectionsText.setText(f"Skipped")
                            
                            
                    except NameError as e:
                        self.DetectionsText.setStyleSheet("color: white")
                        self.DetectionsText.setText(f"ERROR")
                        msg = QtWidgets.QMessageBox() 
                        msg.setIcon(QtWidgets.QMessageBox.Critical) 
                        msg.setWindowIcon(QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_ico.svg'))
                
                                
                                    # setting message for Message Box 
                
                                    
                                    # setting Message box window title 
                        msg.setWindowTitle("Movalabs")     
                                        # setting message for Message Box 
                        msg.setText("Virustotal API.") 
                        msg.setInformativeText(f"Cannot verify the file with virustotal ({e}).")
                                        
                                        
                        msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                        
                                        # start the app 
                                    
                        retval = msg.exec_()
                    try:   
                        if self.UseMetaDefenderApiCheckBox.isChecked() and found != True:
                            # get api key
                            MetaDefenderApiKey = self.MetaDefenderApiKey.text()
                            # check if api key is empty if yes then show error
                            if MetaDefenderApiKey in ["", None]:
                                
                                msg = QtWidgets.QMessageBox() 
                                msg.setIcon(QtWidgets.QMessageBox.Critical) 
                                    
                                        # setting message for Message Box 
                                msg.setText("Metadefender Api.")
                                msg.setInformativeText(f"Metadefender apikey not set.")  
                                        
                                        # setting Message box window title 
                                msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
                                msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                        
                                        # start the app 
                                    
                                retval = msg.exec_()
                            # if api key is not empty then scan the hash of the file
                            else:
                                console.log(f"[+] Verifying (METADEFENDER): {direc}")
                                M_header=({"apikey": MetaDefenderApiKey})
                                M_analysis = requests.get(meta_defender_api + hash, headers=M_header)
                                M_analysis_json = M_analysis.json()
                                M_detections = M_analysis_json["scan_results"]["total_detected_avs"]
                                M_not_detections = M_analysis_json["scan_results"]["total_avs"]
                                half_M_not_detections = M_not_detections / 2
                                # show Meta Defender results
                                self.MetaDefenderWidget.show()
 
                               
                                if M_detections > 3:
                                    scan_end(self, 1, f"File scan: {filepath}")
                                    console.log(F"[red]'{filename}'[white] is infected with [red]'Mal/Trojan.Gen'")
                                    
                                    found = True
                                    self.MetaDefenderDetectionsText.setStyleSheet("color: red")
                                    self.MetaDefenderDetectionsText.setText(f"{str(M_detections)} | {str(M_not_detections)}")
                                    self.IsFileVirusY_N.setStyleSheet("color: red")
                                    if found == False:
                                        self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 10))
                                        self.IsFileVirusY_N.setText("Probably a virus!")
                                    else:
                                        pass
                                if M_detections > half_M_not_detections:
                                    scan_end(self, 1, f"File scan: {filepath}")
                                    console.log(F"[red]'{filename}'[white] is infected with [red]'Mal/Trojan.Gen'")
                                    
                                    self.FilePath.setText("Detection Type:  MetaDefender")
                                    found = True
                                    self.MetaDefenderDetectionsText.setStyleSheet("color: red")
                                    notify(filepath,"status-warning-128.png",f"Detection type: Metadefender","Malware Detected")
                                    self.MetaDefenderDetectionsText.setText(f"{str(M_detections)} | {str(M_not_detections)}")
                                    self.IsFileVirusY_N.setStyleSheet("color: red")
                                    if found == False:
                                        self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 10))
                                        self.IsFileVirusY_N.setText("Probably a virus!")
                                    else:
                                        pass
                                else:
                                    found = False
                                    self.MetaDefenderDetectionsText.setStyleSheet("color: green")
                                    self.MetaDefenderDetectionsText.setText(f"{str(M_detections)} | {str(M_not_detections)}")
                                    if found == False:
                                        self.IsFileVirusY_N.setStyleSheet("color: green")
                                        self.IsFileVirusY_N.setFont(QtGui.QFont("Arial", 12))
                                        self.IsFileVirusY_N.setText("Probably clean")
                                    else:
                                        pass
                               
                        else:
                            self.MetaDefenderDetectionsText.setStyleSheet("color: white")
                            self.MetaDefenderDetectionsText.setText(f"Skipped")
                            
                            
                    except:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: white")
                        self.MetaDefenderDetectionsText.setText(f"ERROR")
                        
                        console.log(F"[yellow]'{filename}'[white] cannot be verified with [yellow]'Metadenfender API'")
                        
                        
                    self.FileHash.setText(f"File Hash: {hashMD5}")
                    if found == True:
                        timeFineshed__ = time();
                        console.log(F"'{filename}' is infected. [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")
                        self.Tabs.setCurrentIndex(2)
                        if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(filepath) < 32000000:
                            self.VirusTotalWidget.show()
                            
                        else:
                            # hide Virus total results since it is not needed
                            self.VirusTotalWidget.hide()
                        # check if meta defender check if on and file is under 120mb
                        if self.UseMetaDefenderApiCheckBox.isChecked() and os.path.getsize(filepath) < 120000000:
                            self.MetaDefenderWidget.show()
                        else:
                            # hide meta defender results since it is not needed
                            self.MetaDefenderWidget.hide()
                        
                        self.IsFileVirusY_N.setStyleSheet("color: red")
                        self.IsFileVirusY_N.setText("YES!")
                        self.QuarentineFileButton.setVisible(True)
                        # delete file button
                        self.QuarentineFileButton.clicked.connect(lambda: removeFile(filepath, filename))
                        # return button
                        self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))
                    
                    else:
                        self.Tabs.setCurrentIndex(2)
            # check if virus total check if on and file is under 32mb
                        if self.UseVirusTotalApiCheckBox.isChecked() and os.path.getsize(filepath) < 32000000:
                            self.VirusTotalWidget.show()
                        else:
                            # hide Virus total results since it is not needed
                            self.VirusTotalWidget.hide()
                        # check if meta defender check if on and file is under 120mb
                        if self.UseMetaDefenderApiCheckBox.isChecked() and os.path.getsize(filepath) < 120000000:
                            self.MetaDefenderWidget.show()
                        else:
                            # hide meta defender results since it is not needed
                            self.MetaDefenderWidget.hide()
                            # set text to clean
                        if suspecious == False:
                            timeFineshed__ = time();
                            console.log(F"'{filename}' is safe. [Done in {round(timeFineshed__ - timeInitial__, 2)}s]")
                            notify(filepath,"status-ok-128.png",f"The file {filename} is safe.","No malware detected")
                            self.IsFileVirusY_N.setStyleSheet("color: green")
                            self.IsFileVirusY_N.setText("NO!")
                            self.FilePath.setText("Detection Type: None")
                            scan_end(self, 0, f"File scan: {filepath}")
                            self.QuarentineFileButton.setVisible(False)
                            # delete file button
                            #self.QuarentineFileButton.clicked.connect(lambda: removeFile(file))
                            # return button
                            self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))
                        else:
                            self.IsFileVirusY_N.setStyleSheet("color: yellow")
                            self.IsFileVirusY_N.setText("YES!")
                            self.QuarentineFileButton.setVisible(True)
                            # delete file button
                            self.QuarentineFileButton.clicked.connect(lambda: removeFile(filepath, filename))
                            # return button
                            self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))     
            else:
                notify(filepath,"status-warning-128.png",f"Selected file is invalid or/and not exist.","File scan")
                
            # display file path
        def decryptFile(current_item):
            console.log(f"[red]The option 'decryptFile' has been disabled for security questions.")
        
        def removeFile(file, filename):
            change_tab_settings(self)
            msg = QtWidgets.QMessageBox() 
            msg.setIcon(QtWidgets.QMessageBox.Warning) 
            msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\antiVirus_ico.svg"))
                                
                                    # setting message for Message Box 
            msg.setText("Alert") 
            msg.setInformativeText("If you press 'OK' the file will deleted. Continue?")
                                    
                                    # setting Message box window title 
            msg.setWindowTitle("Movalabs") 
                                    
                                    # declaring buttons on Message Box 
            msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.No) 
                                    
                                    # start the app 
                                
            retval = msg.exec_()
            
            if retval == 1024:
                try:
                    os.remove(file)

                    notify(file,"status-ok-128.png",f"A malware has been neutralized sucefully.", "Malware neutralized")
                except:

                    notify(file,"status-warning-128.png",f"A error ocurred while neutralizing a malware. This file cannot be neutralized.", "Malware cannot be neutralized")
                    
                
                
            else:
                pass
            
        
        def change_tab_settings(self):
            #182,182,182
            #231,84,128
                self.Tabs.setCurrentIndex(0)
                self.HomeTabButton.setStyleSheet("image: url(res/SideBar/home-outlinedWHITE.svg);\n")
                self.SettingsTabButton.setStyleSheet("image: url(res/SideBar/settings_oWHITE.svg);\n")
                self.QuarantineTabButton.setStyleSheet("image: url(res/SideBar/quarantineWHITE.svg);\n")
                self.HistoryTabButton.setStyleSheet("image: url(res/SideBar/twotone-history.svg);\n")
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(46, 46, 45);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(104, 95, 207);")
                self.CurrentTabQuarantine.setStyleSheet("background-color: rgb(46, 46, 45);")
                self.CurrentTabHistory.setStyleSheet("background-color: rgb(46, 46, 45);")
                
                '''if self.LightModeButton.text() == "Light Mode":
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(81, 89, 97);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(255, 0, 0);")
                else:
                    # light mode
                    self.CurrentTabSettings.setStyleSheet("background-color: rgb(182, 182, 182);")
                    self.CurrentTabHome.setStyleSheet("background-color: rgb(231, 84, 128);")'''
                    


                return

        def change_tab_home(self):
            self.Tabs.setCurrentIndex(1)
            self.SettingsTabButton.setStyleSheet("image: url(res/SideBar/settings_oWHITE.svg);\n")
            self.HomeTabButton.setStyleSheet("image: url(res/SideBar/home-outlinedWHITE.svg);\n")
            self.QuarantineTabButton.setStyleSheet("image: url(res/SideBar/quarantineWHITE.svg);\n")
            self.HistoryTabButton.setStyleSheet("image: url(res/SideBar/twotone-history.svg);\n")
            #104, 95, 207
            self.CurrentTabSettings.setStyleSheet("background-color: rgb(104, 95, 207);")
            self.CurrentTabHome.setStyleSheet("background-color: rgb(46, 46, 45);")
            self.CurrentTabQuarantine.setStyleSheet("background-color: rgb(46, 46, 45);")
            self.CurrentTabHistory.setStyleSheet("background-color: rgb(46, 46, 45);")
            '''if self.LightModeButton.text() == "Light Mode":
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(255, 0, 0);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(81, 89, 97);")
            else:
                    # light mode
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(231, 84, 128);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(182, 182, 182);")
                    
            return	'''
        def change_tab_quarantine(self):
            
            self.Tabs.setCurrentIndex(4)
            self.SettingsTabButton.setStyleSheet("image: url(res/SideBar/settings_oWHITE.svg);\n")
            self.HomeTabButton.setStyleSheet("image: url(res/SideBar/home-outlinedWHITE.svg);\n")
            self.QuarantineTabButton.setStyleSheet("image: url(res/SideBar/quarantineWHITE.svg);\n")
            self.HistoryTabButton.setStyleSheet("image: url(res/SideBar/twotone-history.svg);\n")
            self.CurrentTabSettings.setStyleSheet("background-color: rgb(46, 46, 45);")
            self.CurrentTabHome.setStyleSheet("background-color: rgb(46, 46, 45);")
            self.CurrentTabQuarantine.setStyleSheet("background-color: rgb(104,95,207);")
            self.CurrentTabHistory.setStyleSheet("background-color: rgb(46, 46, 45);")
            
        def change_tab_history(self):
            if self.EnableScanHistory.isChecked() == True:
                self.Tabs.setCurrentIndex(5)
                self.SettingsTabButton.setStyleSheet("image: url(res/SideBar/settings_oWHITE.svg);\n")
                self.HomeTabButton.setStyleSheet("image: url(res/SideBar/home-outlinedWHITE.svg);\n")
                self.QuarantineTabButton.setStyleSheet("image: url(res/SideBar/quarantineWHITE.svg);\n")
                self.HistoryTabButton.setStyleSheet("image: url(res/SideBar/twotone-history.svg);\n")
                self.CurrentTabSettings.setStyleSheet("background-color: rgb(46, 46, 45);")
                self.CurrentTabHome.setStyleSheet("background-color: rgb(46, 46, 45);")
                self.CurrentTabQuarantine.setStyleSheet("background-color: rgb(46, 46, 45);")
                self.CurrentTabHistory.setStyleSheet("background-color: rgb(104,95,207);")
            else:
                change_tab_home(self)
        
        def changetheme(self, config):
            
            style = config["-settings-"]["style"]
            
            if style == "dark":
                config.set('-settings-', 'style', "light")
                qdarktheme.setup_theme("light")
                
                with open(settings_path, 'w') as configf:
                    config.write(configf)
            else:
                config.set('-settings-', 'style', "dark")
                qdarktheme.setup_theme("dark")
                
                with open(settings_path, 'w') as configf:
                    config.write(configf)
        
        def verifyupdates(self):
            DatasetVersion__ = getDatasetVersion();
            noupdate__ = 0;
            update__ = 0;
            __UpdaterResult = update();
            __UpdaterDataResult = update("data")
            msg = QtWidgets.QMessageBox() 
            msg.setIcon(QtWidgets.QMessageBox.Information) 
            msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.svg"))
            
            
            if __UpdaterDataResult == False:
                noupdate__ += 1;
                
            else:
                console.log("[green]Running a dataset update..")
                __UpdaterDataResult__ = updater()
                update__ += 1;
                    
                if __UpdaterDataResult__ == True:
                    msg.setIcon(QtWidgets.QMessageBox.Information) 
                    msg.setInformativeText(f"A dataset update has been completed.")
                    msg.setText("Updater") 
                                        
                                        # setting Message box window title 
                    msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
                    msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                        
                                        # start the app 
                                    
                    retval = msg.exec_()
                    compileHashes();
                        
                else:
                    msg.setIcon(QtWidgets.QMessageBox.Critical) 
                    msg.setInformativeText(f"A dataset update cannot be completed. Verify the terminal for logs.")
                    msg.setText("Updater") 
                                        
                                        # setting Message box window title 
                    msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
                    msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                        
                                        # start the app 
                                    
                    retval = msg.exec_()  
                
            if __UpdaterResult == False:
                noupdate__ += 1;
            
            else:
                __UpdaterResult__ = updater("App")
                
                if __UpdaterResult__ == True:
                    msg.setIcon(QtWidgets.QMessageBox.Information) 
                    msg.setInformativeText(f"Update completed. [A app restart is need.]")
                    msg.setText("Updater") 
                                            
                                            # setting Message box window title 
                    msg.setWindowTitle("Movalabs") 
                                            
                                            # declaring buttons on Message Box 
                    msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                            
                                            # start the app 
                                        
                    retval = msg.exec_()         
                else:
                    msg.setIcon(QtWidgets.QMessageBox.Critical) 
                    msg.setInformativeText(f"A app update cannot be completed. Verify the terminal for logs.")
                    msg.setText("Updater") 
                                        
                                        # setting Message box window title 
                    msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
                    msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                        
                                        # start the app 
                                    
                    retval = msg.exec_()   
           
            if noupdate__ == 2:
                msg.setIcon(QtWidgets.QMessageBox.Information) 
                msg.setInformativeText(f"No update avaliable. \nApp Version: {AppVersion__}\nDataset Version: {DatasetVersion__}")
                msg.setText("Updater") 
                                
                                # setting Message box window title 
                msg.setWindowTitle("Movalabs") 
                                
                                # declaring buttons on Message Box 
                msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                
                                # start the app 
                            
                retval = msg.exec_()
           
        def saveSettings(self):
            config.set('-settings-', 'vrapikey', str(self.VirusTotalApiKey.text()))
            config.set('-settings-', 'virustotal', str(self.UseVirusTotalApiCheckBox.isChecked()))
            config.set('-settings-', 'metadefenderkey', str(self.MetaDefenderApiKey.text()))
            config.set('-settings-', 'metadefender', str(self.UseMetaDefenderApiCheckBox.isChecked()))
            config.set('-settings-', 'automatic_update', str(self.AutomaticUpdates.isChecked()))
            config.set('-settings-', 'scan_history', str(self.EnableScanHistory.isChecked()))
            
            with open(settings_path, 'w') as configfile:
                config.write(configfile)
        
        def browseFolder(MainWindow, self):
            icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoWhite.svg') 
    
        # Adding item on the menu bar 
            tray = QtWidgets.QSystemTrayIcon() 
            tray.setIcon(icon) 
            tray.setVisible(True) 
            
            tray.show()
            folderpath = str(QtWidgets.QFileDialog.getExistingDirectory(MainWindow,
                                                                            "Select a Folder",
                                                                            "FOLDER-PATH",
                                                                            QtWidgets.QFileDialog.ShowDirsOnly))
            
            
            
            if folderpath == "":
                notify(folderpath,"status-warning-128.png",f"Selected folder is invalid or/and not exist.","Folder scan")
            else:
                list_files(folderpath,self, tray)
        # change tabs buttons
        
        self.HomeTabButton.clicked.connect(lambda: change_tab_settings(self))
        
        self.SettingsTabButton.clicked.connect(lambda: change_tab_home(self))
        
        self.QuarantineTabButton.clicked.connect(lambda: change_tab_quarantine(self))
        
        self.HistoryTabButton.clicked.connect(lambda: change_tab_history(self))

        self.SelectFileButton.clicked.connect(lambda: browseFiles(MainWindow, self))
        
        self.SaveSettingsButton.clicked.connect(lambda: saveSettings(self))
        
        self.VerifyUpdatesButton.clicked.connect(lambda: verifyupdates(self))
        
        self.LightModeButton.setVisible(False)
        
        self.SelectFolderButton.clicked.connect(lambda: browseFolder(MainWindow,self))
        
        self.QuickScanButton.clicked.connect(lambda: quickScan(QuickscanFolders, self))
        
        self.RemoveFileButton.clicked.connect(lambda: decryptFile(current_item))
        
        self.historyListWidget.clicked.connect(lambda: scaninfo(self))
        
        self.listwidget.clicked.connect(lambda: listitem(self))
        #Detection Type
        
        
        
        
        
    def retranslateUi(self, Dialog):
        
        if vrapikey != "":
            
            self.VirusTotalApiKey.setText(vrapikey)
        
        if metadefenderkey != "":
            
            self.MetaDefenderApiKey.setText(metadefenderkey)
        
        if virustotal == 'True':
            
            self.UseVirusTotalApiCheckBox.setChecked(True)
        
        if metadefender == 'True':
            
            self.UseMetaDefenderApiCheckBox.setChecked(True)
        
        if automaticUpdates == "True":
            self.AutomaticUpdates.setChecked(True)
        else:
            self.AutomaticUpdates.setChecked(False)
            
        if scanHistory == "True":
            self.EnableScanHistory.setChecked(True)
        else:
            self.EnableScanHistory.setChecked(False)    
        #VerifyUpdatesButton
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", f"Movalabs"))
        
        self.QuarantineTitle.setText(_translate("MainWindow", "Quarantine"))
        self.MalwareBazzarApiCheckBox.setCheckable(False)
        self.MalwareBazzarApiCheckBox.setText(_translate("MainWindow", "Use MalwareBazaar api to check for virus"))
        self.MalwareBazzarApi.setPlaceholderText(_translate("MainWindow", "Your MalwareBazaar api here"))
        self.EnableScanHistory.setText(_translate("MainWindow", "Enable scan history"))
        self.HomeTitle.setText(_translate("MainWindow", "Home"))
        self.SelectFileButton.setText(_translate("MainWindow", "Scan File"))
        self.VerifyUpdatesButton.setText(_translate("MainWindow", "Verify for updates"))
        self.SettingsTitle.setText(_translate("MainWindow", "Settings"))
        self.AutomaticUpdates.setText(_translate("MainWindow", "Automatic updates"))
        self.UseVirusTotalApiCheckBox.setText(_translate("MainWindow", "Use Virus Total api (only files under 32MB)"))
        self.VirusTotalApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Virus Total api Key here"))
        self.SaveSettingsButton.setText(_translate("MainWindow", "Save Config"))
        self.UseMetaDefenderApiCheckBox.setText(_translate("MainWindow", "Use Meta Defender api to check hash"))
        self.MetaDefenderApiKey.setPlaceholderText(_translate("MainWindow", "Enter your Meta Defender api Key here"))
        self.VirusResultsTitle.setText(_translate("MainWindow", "Virus Scan Results"))
        self.LightModeButton.setText(_translate("MainWindow", "Change theme"))
        self.FileName.setText(_translate("MainWindow", "File Name: "))
        self.FilePath.setText(_translate("MainWindow", "File Path: "))
        self.FileHash.setText(_translate("MainWindow", "File Hash: "))
        self.label.setText(_translate("MainWindow", "Detected?"))
        self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
        self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
        self.QuarentineFileButton.setText(_translate("MainWindow", "Remove File"))
        self.label_3.setText(_translate("MainWindow", "Virus Total score"))
        self.DetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_5.setText(_translate("MainWindow", "Detections"))
        self.label_4.setText(_translate("MainWindow", "Meta Defender score"))
        self.MetaDefenderDetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_6.setText(_translate("MainWindow", "Detections"))
        self.QuarantineTitle.setText(_translate("MainWindow", "Quarantine"))
        self.RemoveFileButton.setText(_translate("MainWindow", "Remove file"))
        self.SelectFolderButton.setText(_translate("MainWindow", "Select folder"))
        self.QuickScanButton.setText(_translate("MainWindow", "Quick scan"))
        
     
        

def getDatasetVersion():
    _dataFile = open(current_dir + '\\settings\\dataset.ini')
    DatasetVersion__ = _dataFile.read()
    _dataFile.close()
    
    return DatasetVersion__        

def update(type="app"):
    DatasetVersion__ = getDatasetVersion()
    
    __Page = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/settings/version.ini")
    LatestVersion__ = __Page.content.decode("utf-8")
    


    if type == "app":
        if AppVersion__ == LatestVersion__:
            return False;
            
        else:
            return True;
    
    else:
        
        __PageData = requests.get("https://raw.githubusercontent.com/HSp4m/movalabs/main/settings/dataset.ini")
        DatasetLatest__ = __PageData.content.decode("utf-8")
        
        if DatasetVersion__ == DatasetLatest__:
            return False;
            
        else:
            return True;
        
               
    

        


    
if __name__ == "__main__":
    
    

    
    
    app = QtWidgets.QApplication(sys.argv)
    
    QtWidgets.QWidget().setWindowTitle("Movalabs BETA")
    
    darkmode = True
    qdarktheme.setup_theme("dark", custom_colors={"background": "#000000"})

    
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_Dialog()
    MainWindow.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.svg"))
    verifyModules()
    ui.setupUi(MainWindow)
    
    MainWindow.show()
    
    sys.exit(app.exec_())

