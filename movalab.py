from PyQt5 import QtCore, QtGui, QtWidgets

import yara
import sys
import qdarktheme
import os
import configparser
import requests
from virustotal_python import Virustotal
import hashlib
from cryptography.fernet import Fernet
from datetime import datetime
import json

fernetKey = b'1np9HsC0fRY40-PADY_EylGu1RJfNANVeK_3j80yzpo='

CVERSION = "0.0.3"
fernet = Fernet(fernetKey)

current_dir = os.path.dirname(__file__)
settings_path = current_dir + "/settings/settings.ini"
quarantine_path = current_dir + "/settings/quarantine/"
meta_defender_api = "https://api.metadefender.com/v4/hash/"


fh = open(current_dir + '\\new.yara')
rules = yara.compile(file=fh)

fh.close()



config = configparser.ConfigParser()
config.read(settings_path)

hash = "";

automaticUpdates = config["-settings-"]["automatic_update"]
scanHistory = config["-settings-"]["scan_history"]
style = config["-settings-"]["style"]
virustotal = config["-settings-"]["virustotal"]
vrapikey = config['-settings-']['vrapikey']
metadefenderkey = config["-settings-"]["metadefenderkey"]
metadefender = config["-settings-"]["metadefender"]

historyPaths = []
historyDetections = []
historyFilesDetected = []
historyDetectionsPF = []
historyResult = []

quarantine_itens = os.listdir(quarantine_path)

def scaninfo(self):
    historyResult = []
    __get = 0
    item = self.historyListWidget.currentItem()
    
    current_item = str(item.text())
    print(f"[!] Current item: {current_item}")
    
    __fDetections = current_item.split(", ")
    __fileDetections = __fDetections[1].split(" ")[0]
    
    print(f"[!] Detections: {__fileDetections}")
    for y in historyDetections:
        __fileArray = y.split(": ")
        __fileArray = os.path.split(__fileArray[0])
        __filename = __fileArray[1].split(":")

        __filePath = __fileArray[0] + "/" + __filename[0]
    

        __fileThreat = y.split(": ")[1]
        
        
        for i in historyPaths:
            
            if i in current_item and i in __filePath and __filename[0] not in historyResult and i in historyPaths and __get < int(__fileDetections):
                
                historyResult.append(__filename[0])
                msg = QtWidgets.QMessageBox() 
                msg.setIcon(QtWidgets.QMessageBox.Information)
                msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.ico")) 
                msg.setText(f"Scan ({__filename[0]})")
                msg.setInformativeText(f"Detected: {__fileThreat} \nPath: {__filePath}") 
                msg.setWindowTitle("Movalabs") 
                msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                            
                                            # start the app 
                                        
                retval = msg.exec_()
                
                
                print("[!] Item found in list")
                print(f"[*] Threat: {__fileThreat}")
                print(f"[*] Path: {i}")
                __get += 1
                
            else:
                
                continue
                
        
        
    
        
    if __get == 0:
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

def notify(tray, message, description, image):

    icon = QtGui.QIcon(current_dir + '\\res\\ico\\' + image)
    tray.showMessage(message, description, icon,msecs=2000)
            
    timer = QtCore.QTimer()
    timer.timeout.connect(lambda: tray.hide())
    timer.start(4000)

def list_files(dir, self, tray):
    self.progress.setVisible(True)
    historyFilesDetected = []
    total = 0;
    self.resultWidget.clear()
    detected = 0;
    __totalFiles = 0;
    __filesVerificated = 0;
    
    print("[+] Starting Folder scan!")
    notify(tray,"Starting scan", f"A scan for the folder [{dir}] has been started. The scan mabe take a lot of time", "none")
 
    __totalFiles =sum(len(files) for _, _, files in os.walk(dir))            
    self.progress.setMaximum(__totalFiles)
    
    print(__totalFiles)
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
                    
                    hash = hashlib.md5(file_content).hexdigest()
                    
                    with open(current_dir + "\\hash\\md5.txt", "r") as hashFile:
                    
                        
                        for line in hashFile:
                            
                            for hashes in line.split():
                                
                                if hashes == hash and file_name not in historyFilesDetected:
                                    historyFilesDetected.append(file_name)
                                    
                        
                                    print(f"[*] {file_name} found in [md5.txt] (Hash: {hash})")
                                    
                                    self.resultWidget.insertItem(fulltotal,f"{file_name} (UDS:DangerousObject.HashList)")
                                    self.Tabs.setCurrentIndex(3)
                                    
                                    historyDetections.insert(0,f"{fileR}: UDS:DangerousObject.HashList")
                                else:
                                    continue
                                
                    if matchesFolder != []:
                        
                        detected = 1;
                        self.Tabs.setCurrentIndex(3)
                        for match in matchesFolder:
                            #for rule in rules:
                                #namespace = rule.meta.get('namespace', '?')
                                
                                
                            threat = match.meta.get('threat', "?")
                                
                            if file_name not in historyFilesDetected:
                                if threat == "?":
                                    threat = match.meta.get('malware_family', "?")
                                    if threat == "?":
                                        threat = "UDS:DangerousObject.multi.generic"
                                        historyFilesDetected.append(file_name)
                                        self.resultWidget.insertItem(fulltotal,f"{file_name} ({threat})")

                                        historyDetections.insert(0,f"{fileR}: {threat}")
                                    else:    
                                        historyFilesDetected.append(file_name)
                                        self.resultWidget.insertItem(fulltotal,f"{file_name} ({threat})")

                                        historyDetections.insert(0,f"{fileR}: {threat}")
                                else:
                                    threat = match.meta.get('threat', "?")
                                    historyFilesDetected.append(file_name)
                                    self.resultWidget.insertItem(fulltotal,f"{file_name} ({threat})")

                                    historyDetections.insert(0,f"{fileR}: {threat}")
                                    
                                    
                                    
                        
                        print(f"[*] Malware Found [{threat}]. \n[/] Filename: {file_name}")
                else:
                    continue 
    
        except:
            continue
    if detected == 0:
        print("[*] No file detected with yara list")
    
    if len(historyFilesDetected) == 0:
        self.progress.setVisible(False)
        historyDetectionsPF.append(f"{fileR}: {len(historyFilesDetected)}")
        scan_end(self, len(historyFilesDetected), f"Folder scan: {dir}")
        historyPaths.append(dir)
                       
    else:
        self.progress.setVisible(False)
        historyDetectionsPF.append(f"{fileR}: {len(historyFilesDetected)}")
        scan_end(self, len(historyFilesDetected), f"Folder scan: {dir}") 
        historyPaths.append(dir)
            
    if len(historyFilesDetected) == 0:
        notify(tray,"No malware found", f"No malware found in [{dir}].", "AntiVirus_icoGreen.svg")
    else:
        notify(tray,"Malware found", f"Open the app to see the results.", "AntiVirus_icoRed.svg")
        
        
        
def itens(self):
    count = 0
                
    quarantine_itens = os.listdir(quarantine_path)
    for i in quarantine_itens:
                        
        count += 1
        final = count-1
                            
        self.listwidget.insertItem(final, i)
        


class Ui_2(object):
    def setup(self,Dialog):
        self.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.svg"))
        
    
        '''t = self.vrkeybox = QtWidgets.QLineEdit(Dialog)
        t.move(150, 20)
        t.resize(280,40)
        Dialog.setObjectName("Dialog")
        
        Dialog.resize(600, 300)'''
        
class Ui_Dialog(object):
    
    def setupUi(self, Dialog):
        
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(590, 300)
        MainWindow.setMinimumSize(QtCore.QSize(590, 300))
        MainWindow.setMaximumSize(QtCore.QSize(600, 300))
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
        self.label.setGeometry(QtCore.QRect(5, 160, 111, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label.setFont(font)
        self.label.setObjectName("label")
        self.IsFileVirusY_N = QtWidgets.QLabel(self.VirusScanResults_hidden)
        self.IsFileVirusY_N.setGeometry(QtCore.QRect(5, 190, 101, 31))
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
        self.VirusTotalWidget.setGeometry(QtCore.QRect(120, 160, 181, 71))
        self.VirusTotalWidget.setObjectName("VirusTotalWidget")
        self.label_3 = QtWidgets.QLabel(self.VirusTotalWidget)
        self.label_3.setGeometry(QtCore.QRect(10, 9, 161, 21))
        font = QtGui.QFont()
        font.setPointSize(9)
        self.label_3.setFont(font)
        self.label_3.setAlignment(QtCore.Qt.AlignHCenter|QtCore.Qt.AlignTop)
        self.label_3.setObjectName("label_3")
        self.DetectionsText = QtWidgets.QLabel(self.VirusTotalWidget)
        self.DetectionsText.setGeometry(QtCore.QRect(10, 20, 161, 31))
        font = QtGui.QFont()
        font.setPointSize(9)
        font.setBold(True)
        font.setWeight(75)
        self.DetectionsText.setFont(font)
        self.DetectionsText.setAlignment(QtCore.Qt.AlignCenter)
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
            print(current_item)
            decryptFile(current_item)

        def browseFiles(MainWindow, self):
            
            icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoWhite.svg') 
    
        # Adding item on the menu bar 
            tray = QtWidgets.QSystemTrayIcon() 
            tray.setIcon(icon) 
            tray.setVisible(True) 
            
                    # Creating the options 
            menu = QtWidgets.QMenu() 
            update = QtWidgets.QAction("Update") 
            update.triggered.connect(lambda: Update())
            menu.addAction(update) 
                    
                    
                    # To quit the app 
            quit = QtWidgets.QAction("Quit") 
                    
            quit.triggered.connect(lambda: exitM()) 
            menu.addAction(quit) 
            yaraF = False;
            hashF = False;        
                    # Adding options to the System Tray 
            tray.setContextMenu(menu)
            
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
            
            if os.path.isfile(filepath) and filename not in ["movalab.py", "new.yara"]:
                
                
                vrapikey = config['-settings-']['vrapikey']
                direc = filepath
                
                file = open(filepath, "rb")
                file_content = file.read()
                suspecious = False;
                found = False;
                with open(direc,'rb') as filef:
                    print("[+] Starting YARA RULES verification")
                    matches = rules.match(data=filef.read())
                    
                
                if matches != []:
                    found = True
                    print(F"[*] FOUND: {matches}")
                    
                    for match in matches:
                        for rule in rules:
                            
                            namespace = rule.meta.get('namespace', '?')
                            threat = rule.meta.get('threat', '?')
                            if namespace == f"{match}":
                                yaraF = True;
                                scan_end(self, "yara", "File scan")
                                notify(tray,"Malware Detected", f"Type: {threat} \nDetection: Yara rules", "AntiVirus_icoRed.svg")
                                self.FilePath.setText(f"Detection Type: Yara Rules ({threat})")
                                
                                
                
                    
                hash = hashlib.md5(file_content).hexdigest()
                
                file.close()
                print(hash)
                
                
                
                with open("hash\\md5.txt", "r") as hashFile:
                    
                    print("[+] Reading [md5.txt]")
                    for line in hashFile:
                        #print(line)
                        for hashes in line.split():
                            
                            if hashes == hash:
                                notify(tray,"Malware Found", "Detection type: Hash List", "AntiVirus_icoRed.svg")
                                self.FilePath.setText("Detection Type:  Hash List")
                                print(f"[*] File found in [md5.txt] (Hash: {hash})")
                                scan_end(self, "hash", "File scan")
                                found = True
                                pass;
                            
                        if found == True:
                            pass;
                        
                if found == True:
                        pass;
                else:
                    print("[-] File not found in [md5.txt]")       
                            
                hashFile.close()
                            
                
                detections = 0;
                
                try:
                    if self.UseVirusTotalApiCheckBox.isChecked() and found != True and os.path.getsize(filepath) < 32000000:
                        if vrapikey != '':
                            if direc != '':
                                if os.path.isfile(direc):
                                    found = False;
                                    
                                    print(f"[+] Verifying: {direc}")
                                    files = {"file": (os.path.basename(filepath), open(os.path.abspath(filepath), "rb"))}
                                    vtotal = Virustotal(API_KEY=vrapikey)
                                    resp = vtotal.request("files", files=files, method="POST")
                                    id = resp.data["id"]
                                    headers = {"x-apikey": vrapikey}
                                    analysis = requests.get(f"https://www.virustotal.com/api/v3/analyses/{id}", headers=headers)
                                    analysis_json = analysis.json()
                                    detections = analysis_json["data"]["attributes"]["stats"]["malicious"]
                                    not_detections = analysis_json["data"]["attributes"]["stats"]["undetected"]
                                    
                                    
                                    if not_detections == 0:
                                        self.DetectionsText.setStyleSheet("color: red")
                                        self.DetectionsText.setText(f"{str(detections)} INVALID | {str(not_detections)}")
                                        found = False;
                                    if detections > 10:
                                        scan_end(self, detections, "File scan")
                                        notify(tray,"Malware Found", "Detection type: VirusTotal", "AntiVirus_icoRed.svg")
                                        self.FilePath.setText("Detection Type:  Virustotal")
                                        self.DetectionsText.setStyleSheet("color: red")
                                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                                        found = True
                                        
                                    elif detections > 4:
                                        scan_end(self, detections, "File scan")
                                        notify(tray,"Malware Found", "Detection type: VirusTotal", "AntiVirus_icoRed.svg")
                                        self.FilePath.setText("Detection Type:  Virustotal")
                                        self.DetectionsText.setStyleSheet("color: yellow")
                                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                                        found = True;
                                        
                                    elif detections > not_detections:
                                        scan_end(self, detections, "File scan")
                                        notify(tray,"Malware Found", "Detection type: VirusTotal", "AntiVirus_icoRed.svg")
                                        self.FilePath.setText("Detection Type:  Virustotal")
                                        self.DetectionsText.setStyleSheet("color: red")
                                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                                        found = True;
                                    else:
                                        
                                        found = False;
                                        self.DetectionsText.setStyleSheet("color: white")
                                        
                                        self.DetectionsText.setText(f"{str(detections)} | {str(not_detections)}")
                                    print(f"[?] Scan end")
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
                            self.label.setText("")
                            msg = QtWidgets.QMessageBox() 
                            msg.setIcon(QtWidgets.QMessageBox.Critical) 
                                
                                    # setting message for Message Box 
                            msg.setText("Apikey not set.") 
                                    
                                    # setting Message box window title 
                            msg.setWindowTitle("ERROR") 
                                    
                                    # declaring buttons on Message Box 
                            msg.setStandardButtons(QtWidgets.QMessageBox.Ok) 
                                    
                                    # start the app 
                                
                            retval = msg.exec_()
                    else:
                        
                        self.DetectionsText.setStyleSheet("color: white")
                        self.DetectionsText.setText(f"Skipped")
                        print(f"[?] Scan end")
                        
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
                        if MetaDefenderApiKey == "":
                            
                            msgBox = QtWidgets.QMessageBox()
                            msgBox.setIcon(QtWidgets.QMessageBox.Critical)
                            msg.setWindowIcon(QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_ico.svg'))

                            msg.setWindowTitle("Movalabs")
                            msgBox.setText("Error")
                            msgBox.setInformativeText(f"""\
        Please enter a valid Meta Defender API key.
                            """)
                            # remove window title bar
                            msgBox.setWindowFlags(QtCore.Qt.WindowStaysOnTopHint)
                            msgBox.setWindowFlags(QtCore.Qt.FramelessWindowHint)
                            msgBox.exec_()
                        # if api key is not empty then scan the hash of the file
                        else:
                            print(f"[+] Verifying (METADEFENDER): {direc}")
                            M_header=({"apikey": MetaDefenderApiKey})
                            M_analysis = requests.get(meta_defender_api + hash, headers=M_header)
                            M_analysis_json = M_analysis.json()
                            M_detections = M_analysis_json["scan_results"]["total_detected_avs"]
                            M_not_detections = M_analysis_json["scan_results"]["total_avs"]
                            half_M_not_detections = M_not_detections / 2
                            # show Meta Defender results
                            self.MetaDefenderWidget.show()
                            # if detections more than half of not detections print red
                            print(f"[NOT: {M_not_detections}] [HALFNOT: {half_M_not_detections}]")
                            if M_detections > 3:
                                scan_end(self, M_detections, "File scan")
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
                                scan_end(self, M_detections, "File scan")
                                self.FilePath.setText("Detection Type:  MetaDefender")
                                found = True
                                self.MetaDefenderDetectionsText.setStyleSheet("color: red")
                                notify(tray,"Malware Found", "Detection type: MetaDefender", "AntiVirus_icoRed.svg")
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
                            print(f"[?] Scan end")
                    else:
                        self.MetaDefenderDetectionsText.setStyleSheet("color: white")
                        self.MetaDefenderDetectionsText.setText(f"Skipped")
                        print(f"[?] Scan end")
                        
                except:
                    self.MetaDefenderDetectionsText.setStyleSheet("color: white")
                    self.MetaDefenderDetectionsText.setText(f"ERROR")
                    notify(tray,"Metadefender API", "Cannot verify the file with metadefender.", "AntiVirus_ico.ico")
                    
                    
                self.FileHash.setText(f"File Hash: {hash}")
                if found == True:
                    #print("why?")
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
                    
                    self.IsFileVirusY_N.setStyleSheet("color: red")
                    self.IsFileVirusY_N.setText("YES!")
                    self.QuarentineFileButton.setVisible(True)
                    # delete file button
                    self.QuarentineFileButton.clicked.connect(lambda: quarentineFile(filepath, filename))
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
                        notify(tray,"No malware found", f"No malware found in {filename}.", "AntiVirus_icoGreen.svg")
                        self.IsFileVirusY_N.setStyleSheet("color: green")
                        self.IsFileVirusY_N.setText("NO!")
                        self.FilePath.setText("Detection Type: None")
                        scan_end(self, 0, "File scan")
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
                        self.QuarentineFileButton.clicked.connect(lambda: quarentineFile(filepath, filename))
                        # return button
                        self.ReturnToHomeTabButton.clicked.connect(lambda: self.Tabs.setCurrentIndex(0))     
            else:
                notify(tray,"File Dialog", "Invalid selected file.", "AntiVirus_ico.ico")
                
            # display file path
        def decryptFile(current_item):
            
    
        # Adding item on the menu bar 
            
            if current_item != None:
                icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoWhite.svg') 
                tray = QtWidgets.QSystemTrayIcon() 
                tray.setIcon(icon) 
                tray.setVisible(True)
                notify(tray, "File Decrypted", f"The file [{current_item}] has been decrypted.", "AntiVirus_icoYellow.svg")
                tray.setVisible(False)
                self.listwidget.takeItem(self.listwidget.currentRow())
                with open(current_dir + "\\settings\\quarantine\\" + current_item, "rb") as filef:
                    file_content = filef.read()
                    
                    
                decryptF = fernet.decrypt(file_content)
                
                with open(current_dir + "\\settings\\quarantine\\" + current_item, "wb") as filef:
                    filef.write(decryptF)
            else:
                msg = QtWidgets.QMessageBox() 
                msg.setIcon(QtWidgets.QMessageBox.Warning) 
                msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\antiVirus_ico.svg"))
                                    
                                        # setting message for Message Box 
                msg.setText("No file") 
                msg.setInformativeText("Click in a name on the list and try again.")
                                        
                                        # setting Message box window title 
                msg.setWindowTitle("Movalabs") 
                                        
                                        # declaring buttons on Message Box 
                msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.No) 
                                        
                                        # start the app 
                                    
                retval = msg.exec_()
        
        def quarentineFile(file, filename):
            
            msg = QtWidgets.QMessageBox() 
            msg.setIcon(QtWidgets.QMessageBox.Warning) 
            msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\antiVirus_ico.svg"))
                                
                                    # setting message for Message Box 
            msg.setText("Alert") 
            msg.setInformativeText("If you press 'OK' the file will be encrypted and renamed to other name. Continue?")
                                    
                                    # setting Message box window title 
            msg.setWindowTitle("Movalabs") 
                                    
                                    # declaring buttons on Message Box 
            msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.No) 
                                    
                                    # start the app 
                                
            retval = msg.exec_()
            
            if retval == 1024:
                change_tab_quarantine(self)
                
                
                '''fileName, old_extension = os.path.splitext(filename)
                new_name = fileName + ".movalabs"
                
                
                
                os.rename(file, new_name)'''
                with open(file, "rb") as filef:
                    file_content = filef.read()
                
                icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoGreen.svg') 
                tray = QtWidgets.QSystemTrayIcon() 
                tray.setIcon(icon) 
                tray.setVisible(True)
                notify(tray, "File Neutralized", f"The file [{file}] has been moved to quarantine.", "AntiVirus_icoGreen.svg")
                tray.setVisible(False)
                
                crypt = fernet.encrypt(file_content)
                #print(crypt)
                with open(file, "wb") as filef:
                    filef.write(crypt)
                quarantine_itens = os.listdir(current_dir + "\\settings\\quarantine\\")
                self.listwidget.clear()
                os.rename(file,current_dir + "\\settings\\quarantine\\" + filename)
                decrypt = fernet.decrypt(crypt)
                #print(decrypt)
                itens(self)
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
            msg = QtWidgets.QMessageBox() 
            msg.setIcon(QtWidgets.QMessageBox.Information) 
            msg.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.svg"))
                        
                            # setting message for Message Box 
            msg.setInformativeText(f"No update avaliable. \nCurrent Version: {CVERSION}")
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
        #SelectFolderButton
        def browseFolder(MainWindow, self):
            icon = QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_icoWhite.svg') 
    
        # Adding item on the menu bar 
            tray = QtWidgets.QSystemTrayIcon() 
            tray.setIcon(icon) 
            tray.setVisible(True) 
            
                    # Creating the options 
            menu = QtWidgets.QMenu() 
            update = QtWidgets.QAction("Update") 
            update.triggered.connect(lambda: Update())
            menu.addAction(update) 
                    
                    
                    # To quit the app 
            quit = QtWidgets.QAction("Quit") 
                    
            quit.triggered.connect(lambda: exitM()) 
            menu.addAction(quit) 
                    
                    # Adding options to the System Tray 
            tray.setContextMenu(menu)
            
            tray.show()
            folderpath = str(QtWidgets.QFileDialog.getExistingDirectory(MainWindow,
                                                                            "Select a Folder",
                                                                            "FOLDER-PATH",
                                                                            QtWidgets.QFileDialog.ShowDirsOnly))
            
            
            
            if folderpath == "":
                notify(tray,"Folder Dialog", "Invalid folder selected.", "other\\icons8-palm-scan-100.png")
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
        self.label.setText(_translate("MainWindow", "Virus?"))
        self.IsFileVirusY_N.setText(_translate("MainWindow", "YES"))
        self.ReturnToHomeTabButton.setText(_translate("MainWindow", "Return"))
        self.QuarentineFileButton.setText(_translate("MainWindow", "Quarentine File"))
        self.label_3.setText(_translate("MainWindow", "Virus Total score"))
        self.DetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_5.setText(_translate("MainWindow", "Detections"))
        self.label_4.setText(_translate("MainWindow", "Meta Defender score"))
        self.MetaDefenderDetectionsText.setText(_translate("MainWindow", "0 | 0"))
        self.label_6.setText(_translate("MainWindow", "Detections"))
        self.QuarantineTitle.setText(_translate("MainWindow", "Quarantine"))
        self.RemoveFileButton.setText(_translate("MainWindow", "Remove file"))
        self.SelectFolderButton.setText(_translate("MainWindow", "Select folder"))
        
     
        
def exitM():
        msg = QtWidgets.QMessageBox()
        msg.setWindowIcon(QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_ico.svg'))
        msg.setIcon(QtWidgets.QMessageBox.Warning) 
                            
                                # setting message for Message Box 
        msg.setInformativeText("If you exit you now maybe unprotected. Are you sure you want to exit?")
        msg.setText("Exit confirmation") 
                                
                                # setting Message box window title 
        msg.setWindowTitle("Movalabs") 
                                
                                # declaring buttons on Message Box 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.Cancel) 
                                
                                # start the app 
                            
        retval = msg.exec_()
            
        if retval == 1024:
                
            app.exit()
                
        elif retval == 4194304:
                
            print("Canceled.")
            pass
        
def Update():
        msg = QtWidgets.QMessageBox() 
        msg.setIcon(QtWidgets.QMessageBox.Information) 
        msg.setWindowIcon(QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_ico.svg'))
                
                                
                                    # setting message for Message Box 
                
                                    
                                    # setting Message box window title 
        msg.setWindowTitle("Movalabs") 
                                    # setting message for Message Box 
        msg.setInformativeText("Update now?")
        msg.setText("Update avaliable") 
                                    
                                    # setting Message box window title 
                
                                    
                                    # declaring buttons on Message Box 
        msg.setStandardButtons(QtWidgets.QMessageBox.Ok | QtWidgets.QMessageBox.No) 
                                    
                                    # start the app 
                                
        retval = msg.exec_()
                
        if retval == 1024:
                    
            msg = QtWidgets.QMessageBox() 
            msg.setIcon(QtWidgets.QMessageBox.Critical) 
            msg.setWindowIcon(QtGui.QIcon(current_dir + '\\res\\ico\\AntiVirus_ico.svg'))
                    
                                    
                                        # setting message for Message Box 
                    
                                        
                                        # setting Message box window title 
            msg.setWindowTitle("Movalabs") 
                                        # setting message for Message Box 
            msg.setInformativeText("Update server not found. Try again leter.")
            msg.setText("ERROR") 
                                        
                                        # setting Message box window title 
                    
                                        
                                        # declaring buttons on Message Box 
            msg.setStandardButtons(QtWidgets.QMessageBox.Ok)
                    
            retval = msg.exec_()
                    
        elif retval == 65536:
                            
            print(f"No [{retval}]")
                        
        else:
                        
            print(f"? [{retval}]")
    
    
def __modules__Verify():
    __missing = 0
    
    if os.path.isfile(current_dir + "\\new.yara"):
        
        print("[*] Yara: OK")
    else:
        __missing += 1
        print("[-] Yara: ERROR")
        
    if os.path.isdir(current_dir + "\\res\\SideBar"):
        
        print("[*] SideBar folder: OK")
        
        if os.path.isfile(current_dir + "\\res\\SideBar\\home-outlinedWHITE.svg") and os.path.isfile(current_dir + "\\res\\SideBar\\settings_oWHITE.svg") and os.path.isfile(current_dir + "\\res\\SideBar\\quarantineWHITE.svg"):
            print("[*] SideBar icons: OK")
        
        else:
            print("[-] SideBar icons: ERROR")
            __missing += 1
        
    else:
        __missing += 1
        print("[-] SideBar icons: ERROR")
           
    if os.path.isfile(settings_path):
        print("[*] Settings: OK")
        
    else:
        __missing += 1
        print("[-] Settings: CRITICAL ERROR")
    
    if __missing == 0:
        print("[OK] Loaded")
        
    else:
        
        print(F"[ERROR] Cannot load. \n{__missing} erros")
        exit()
    
if __name__ == "__main__":
    
    

    __modules__Verify()
    
    app = QtWidgets.QApplication(sys.argv)
    
    QtWidgets.QWidget().setWindowTitle("Movalabs BETA")
    
    if style == "dark":
        darkmode = True
        qdarktheme.setup_theme("dark", custom_colors={"background": "#000000"})
        #121214
        #0d0d15
        #111827
    else:
        darkmode = False
        qdarktheme.setup_theme("light")
    
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_Dialog()
    MainWindow.setWindowIcon(QtGui.QIcon(current_dir + "\\res\\ico\\AntiVirus_ico.svg"))
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())

