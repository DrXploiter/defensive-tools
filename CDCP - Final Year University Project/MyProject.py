"""#######################################################################################################
Author: AGA (AKA DrXploiter)
Program Name: CDCP (Cloud Data Confidentiality Protector)
Date Created: 12th January 2020
Description: A graphical user interface to aid users in protecting/improving cloud data confidentiality.
Open source license agreement statement: This software has been developed by me, AGA, on behalf of my final year
cyber-security University project. This software can be modified in any way to aid
the user in catering to their individualistic needs. However, this software should not be sold or distributed
without consent from me and my University. Those who modify this software should 
still cite the original source as the orginal creator of the program; please contact me directly regarding
how to correctly cite my source if you wish to use it for any of your projects. If you have any issues
during set-up, please contact me.
#########################################################################################################"""


#Module importations
from tkinter import *
from tkinter import ttk
from ttkthemes import themed_tk as tk
import mysql.connector as mysql
import os.path
from tkinter import filedialog
from tkinter.ttk import Combobox
from itertools import zip_longest
import os
import binascii
import uuid
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import pyautogui
from itertools import chain
import time
from tkinter import messagebox
from datetime import datetime
import hashlib
from tkinter import Entry
import shutil

# ----------------------------------
#variable initialisations
filename = ''
filesize = ''
fileDir = ''
idsList = ''
fileDateCreated = ''
fragmentName_One = ''
fragmentName_Two = ''
fragmentName_Three = ''
fragmentName_Four = ''
selectedFileID = ''
AESkey = 0
selectedEncryptionOption = ''
RandomKeyString = ''
OTPkey1 = ''
OTPkey2 = ''
OTPkey3 = ''
OTPkey4 = ''
hostEntry = ''
userEntry = ''
passwordEntry = ''
localDownloadLocation_Entry = ''
SQLhost = ''
entropyThresholdEntry = ''


#set path of rclonepath
rclonepath = (r'additional_Files\rclone\rclone.exe')

#set date time
dateTimeNow = datetime.now()

#--------------------------------------------------------------------
#initial settings infomration-------------------------------------------
SQLhost = 'localhost'
SQLuser = 'root'
SQLpassword = 'cisco'
localDownloadLocation = '.'

def InitialSettings():
    global SQLhost, SQLuser, SQLpassword, EntropyThreshold, localDownloadLocation
    SQLhost = hostEntry.get()
    SQLuser = userEntry.get()
    SQLpassword = passwordEntry.get()
    EntropyThreshold = entropyThresholdEntry.get()
    localDownloadLocation = localDownloadLocation_Entry.get()
    infoMessageBox('settings', 'Settings changed')



def db_con():
    con = mysql.connect(host=SQLhost, user=SQLuser, password=SQLpassword, database="filefrag")
    cursor = con.cursor()
    return con, cursor

#Main Program Functions-------------------------------------------------------------------------------------------
# Initial database insertion
def download_provider(CSPname, filename):
    # global download
    os.system(rclonepath + ' copy ' + CSPname + ':\\' + filename + ' ' + '.')
    print(localDownloadLocation)

def upload_provider(CSPname, filename):
    os.system(rclonepath + ' copy ' + filename + ' ' + CSPname + ':\\')

def delete_provider(CSPname, filename):
    # global download
    os.system(rclonepath + ' deletefile ' + CSPname + ':' + filename)

def OTPencryption(filename, OTPkey):
    Thefile = bytearray(open(filename, 'rb').read())
    string = (OTPkey).encode('utf-8')

    # ensure that the length is equal to the the smaller one upon xoring
    size = len(Thefile)

    while len(string) < size:
        string += string

    xord_byte_list = bytearray(size)

    # perform xor operation between the binary string and the file to encrypt
    for i in range(size):
        xord_byte_list[i] = Thefile[i] ^ string[i]

    #  Now perform the XOR between the binary string and the file to decrypt
    # open('encrypted_'+filename, 'wb').write(xord_byte_list)
    open(filename, 'wb').write(xord_byte_list)

def OTPdecryption(filenameOTP, OTPkey):
    # Read file binary data with key binary data to peform xor
    theFile = bytearray(open(filenameOTP, 'rb').read())
    string = (OTPkey).encode('utf-8')

    # ensure that the length  to be equal to the the smaller one upon xoring
    size = len(theFile)

    while len(string) < size:
        string += string

    xord_byte_array = bytearray(size)

    # perform the Xor between the binary string and the file to decrypt
    for i in range(size):
        xord_byte_array[i] = theFile[i] ^ string[i]

    # Write the Xored bytes to the output file
    open(filenameOTP, 'wb').write(xord_byte_array)

def encryptAES(key, filename):
    chunksize = 64 * 1024
    outputFile = filename + '.e'
    filesize = str(os.path.getsize(filename)).zfill(16)
    IV = Random.new().read(16)

    encryptor = AES.new(key, AES.MODE_CBC, IV)

    with open(filename, 'rb') as infile:
        with open(outputFile, 'wb') as outfile:
            outfile.write(filesize.encode('utf-8'))
            outfile.write(IV)

            while True:
                chunk = infile.read(chunksize)
                print(chunk)
                if len(chunk) == 0:
                    break
                elif len(chunk) % 16 != 0:
                    chunk += b' ' * (16 - (len(chunk) % 16))

                outfile.write(encryptor.encrypt(chunk))
    infile.close()
    outfile.close()

def decryptAES(key, filename):
    # specify the fragment ids so that they can be decrypted by each one
    chunksize = 64 * 1024
    outputFile = filename.replace('.e', '')

    with open(filename, 'rb') as infile:
        decoded = infile.read(16).decode('utf-8')  # save in variable
        filesize = int(decoded)
        IV = infile.read(16)

        decryptor = AES.new(key, AES.MODE_CBC, IV)

        with open(outputFile, 'wb') as outfile:
            while True:
                chunk = infile.read(chunksize)

                if len(chunk) == 0:
                    break

                outfile.write(decryptor.decrypt(chunk))
            outfile.truncate(filesize)
def getKey(password):
    hasher = SHA256.new(password.encode('utf-8'))
    return hasher.digest()
# --------------End Of...Additional Functions-------------------
# --------------Button Functions-------------------------------
def infoMessageBox(title, message):
    messagebox.showinfo(title, message)


def runDefrag():
    con, cursor = db_con()
    print(
        'one: ' + fragmentName_One + ' ' + 'two: ' + fragmentName_Two + ' ' + 'three: ' + fragmentName_Three + ' ' + 'four: ' + fragmentName_Four)
    idsList = [fragmentName_One, fragmentName_Two, fragmentName_Three, fragmentName_Four]
    print('defrag: ' + str(idsList))
    allfragments = idsList
    compiledFrags = []
    for eachFrag in allfragments:
        with open(eachFrag, 'rb') as f:
            content = f.read()
            hexValues = binascii.hexlify(content)

        hexValue = (str(hexValues.decode('utf-8')))
        compiledFrags.append(hexValue)

    orginalBytes = ""

    # using zip, pair all elements into a new list > then assign each byte into orginalBytes variable for final reconstruction
    raidINV = (zip_longest(*compiledFrags))
    for x in raidINV:
        for y in x:
            if (y != None): # do not include the empty parts of the list which are None
                orginalBytes = orginalBytes + y

    # get the amount of padding from the file
    cursor.execute("SELECT AmountOfPadding FROM filefrag.files WHERE File_id='" + str(selectedFileID) + "';")
    rows = cursor.fetchone()
    for row in rows:
        amountOfPadding = row

    if int(amountOfPadding) > 0:  # if there is no padding then dont remove anything at all
        # remove padding based on number of padding
        orginalBytes = orginalBytes[:-int(amountOfPadding)]
        print('number of padding: ' + str(amountOfPadding))
        print('remove padding: ' + orginalBytes)

    # get filename of selected file for download based on id
    cursor.execute("SELECT Filename FROM filefrag.files WHERE File_id='" + str(selectedFileID) + "';")
    filename = cursor.fetchone()
    filename = filename[0]
    print('>>>>' + str(filename[0]))

    # file = open(NameofFile + '.' + fileExtentionName, "wb")
    file = open(filename, "wb")
    hexDataInput = binascii.a2b_hex(orginalBytes)
    file.write(hexDataInput)
    file.close()
    outputLogbox.insert(INSERT, '\nDefragmentation completed at: ' + str(dateTimeNow)[:-7] + '\n')
    infoMessageBox('CDCP Status', 'Downloaded Successfully')
    try:
        shutil.move(filename, localDownloadLocation) #move to local download location
    except:
        pass


    try:
        #remove all unencrypted fragments left over
        os.remove(fragmentName_One)
        os.remove(fragmentName_Two)
        os.remove(fragmentName_Three)
        os.remove(fragmentName_Four)
        # remove all encrypted fragments left over
        os.remove(fragmentName_One+str('.e'))
        os.remove(fragmentName_Two + str('.e'))
        os.remove(fragmentName_Three + str('.e'))
        os.remove(fragmentName_Four+ str('.e'))
    except:
        print('fragments do not exist')

def QueryAndDownloadFile():  # Query file info for download
    outputLogbox.insert(INSERT, '\nRequested file for download at: ' + str(dateTimeNow)[:-7] + '\n')
    con, cursor = db_con()
    cursor = con.cursor(buffered=True)  # added for mitigating against pervious error

    selected = listbox.curselection()[0]  # grab index of selected element

    fileIDStore = show()
    # print(fileIDStore[selected])
    global selectedFileID
    selectedFileID = (fileIDStore[selected])
    cursor.execute("""SELECT l.Location_Description, Fragment_id
           FROM filefrag.files as f
           INNER JOIN filefrag.fragments as g on f.File_id = g.File_id
           INNER JOIN filefrag.location l on g.Location_id = l.Location_id
           WHERE f.File_id = '""" + str(selectedFileID) + """'ORDER BY Index_ ASC;""")
    rows = cursor.fetchall()
    global fragmentName_One, fragmentName_Two, fragmentName_Three, fragmentName_Four
    for row in rows:
        # fragment locations
        fragmentLoc_One = rows[0][0]
        fragmentLoc_Two = rows[1][0]
        fragmentLoc_Three = rows[2][0]
        fragmentLoc_Four = rows[3][0]
        #fragment ids
        fragmentName_One = rows[0][1]
        fragmentName_Two = rows[1][1]
        fragmentName_Three = rows[2][1]
        fragmentName_Four = rows[3][1]

    # check the encryption type or lack there of by fetching the encryption id of the file
    cursor.execute("SELECT Encryption_id from filefrag.fragments where File_id='" + str(selectedFileID) + "';")
    encryptionID = cursor.fetchone()
    encryptionID = encryptionID[0]
    #check the type of encryption used
    cursor.execute("SELECT Type_ FROM filefrag.encryption WHERE Encryption_id='" + str(encryptionID) + "';")
    rows_encryptionData = cursor.fetchone()
    #get encryption type
    encryptionType = rows_encryptionData[0]
    print('type: ' + encryptionType)

    # take the file id of the selected listbox item and perform a look-up of its encryption type.. if AES then perform lookup of key
    if encryptionType == ('AES-256'):

        download_provider(fragmentLoc_One, fragmentName_One + '.e')
        download_provider(fragmentLoc_Two, fragmentName_Two + '.e')
        download_provider(fragmentLoc_Three, fragmentName_Three + '.e')
        download_provider(fragmentLoc_Four, fragmentName_Four + '.e')
        outputLogbox.insert(INSERT, '\nFragments downloaded at: ' + str(dateTimeNow) + '\n')
        fragmentNames = [fragmentName_One + '.e', fragmentName_Two + '.e', fragmentName_Three + '.e',
                         fragmentName_Four + '.e']

        # fetch the encryption id of the file
        cursor.execute("SELECT Encryption_id from filefrag.fragments where File_id='" + str(selectedFileID) + "';")
        encryptionID = cursor.fetchone()
        encryptionID = encryptionID[0]

        # fetch the encryption type and key infotmation of the file based on its encryption id
        cursor.execute("SELECT Type_, Key1_ FROM filefrag.encryption WHERE Encryption_id='" + str(encryptionID) + "';")
        rows_encryptionData = cursor.fetchall()

        for rows in rows_encryptionData:
            encryptionTypeDB = rows[0]
            RandomKeyString = rows[1]
        print('type: ' + encryptionTypeDB)
        print('key: ' + RandomKeyString)

        # after downloading all the fragments, decrypt
        for i in fragmentNames:
            decryptAES(getKey(RandomKeyString), i)
        outputLogbox.insert(INSERT, 'Fragments decrypted with AES at: ' + str(dateTimeNow) + '\n')

    if encryptionType == ('OTP'):
        download_provider(fragmentLoc_One, fragmentName_One)
        download_provider(fragmentLoc_Two, fragmentName_Two)
        download_provider(fragmentLoc_Three, fragmentName_Three)
        download_provider(fragmentLoc_Four, fragmentName_Four)

        # fetch the encryption id of the file
        cursor.execute("SELECT Encryption_id from filefrag.fragments where File_id='" + str(selectedFileID) + "';")
        encryptionID = cursor.fetchone()
        encryptionID = encryptionID[0]

        print('OTP encryptionID: '+str(encryptionID))

        # fetch the encryption type and key information of the file based on its encryption id
        cursor.execute("SELECT Type_, Key1_, Key2_, Key3_, Key4_ FROM filefrag.encryption WHERE Encryption_id='" + str(encryptionID) + "';")
        rows_encryptionData = cursor.fetchall()

        for rows in rows_encryptionData:
            key1 = rows[1]
            key2 = rows[2]
            key3 = rows[3]
            key4 = rows[4]

        OTPdecryption(fragmentName_One, key1)
        OTPdecryption(fragmentName_Two, key2)
        OTPdecryption(fragmentName_Three, key3)
        OTPdecryption(fragmentName_Four, key4)

    if encryptionType == ('None'):
        download_provider(fragmentLoc_One, fragmentName_One)
        download_provider(fragmentLoc_Two, fragmentName_Two)
        download_provider(fragmentLoc_Three, fragmentName_Three)
        download_provider(fragmentLoc_Four, fragmentName_Four)

    outputLogbox.insert(INSERT, '\n Download completed at ' + str(dateTimeNow)[:-7] + '\n')
    runDefrag()

def renameFile():
    prompt = messagebox.askyesno("rename file?", "Are you sure you want to rename this file?")
    if prompt == True:
        con, cursor = db_con()
        selected = listbox.curselection()[0]  # grab index of selected element
        fileIDStore = show()
        global selectedFileID
        selectedFileID = (fileIDStore[selected])

        print(selectedFileID)

        cursor.execute("UPDATE `filefrag`.`files` SET `Filename` = '%s' WHERE (`File_id` = '%s');" % (
        renameFile_entry.get(), selectedFileID))
        con.commit()
        con.close()
        show()
        infoMessageBox('rename file?', 'File renamed')
        outputLogbox.insert(INSERT, '\n File renamed at: '+str(dateTimeNow)[:-7]+'\n')
    else:
        infoMessageBox('rename file?', 'No changes made')

def deleteRecord():
    prompt = messagebox.askyesno("delete file?", "Are you sure you want to delete this file?")
    if prompt == True:
        con, cursor = db_con()
        cursor = con.cursor(buffered=True)  # added for mitigating against PREVIOUS error


        selected = listbox.curselection()[0]  # grab index of selected element

        fileIDStore = show()
        # print(fileIDStore[selected])
        global selectedFileID
        selectedFileID = (fileIDStore[selected])
        cursor.execute("""SELECT l.Location_Description, Fragment_id
                 FROM filefrag.files as f
                 INNER JOIN filefrag.fragments as g on f.File_id = g.File_id
                 INNER JOIN filefrag.location l on g.Location_id = l.Location_id
                 WHERE f.File_id = '""" + str(selectedFileID) + """'ORDER BY Index_ ASC;""")
        rows = cursor.fetchall()
        global fragmentName_One, fragmentName_Two, fragmentName_Three, fragmentName_Four
        # fragment locations
        fragmentLoc_One = rows[0][0]
        fragmentLoc_Two = rows[1][0]
        fragmentLoc_Three = rows[2][0]
        fragmentLoc_Four = rows[3][0]
        # fragment ids
        fragmentName_One = rows[0][1]
        fragmentName_Two = rows[1][1]
        fragmentName_Three = rows[2][1]
        fragmentName_Four = rows[3][1]

        # check the encryption type or lack there of by fetching the encryption id of the file
        cursor.execute("SELECT Encryption_id from filefrag.fragments where File_id='" + str(selectedFileID) + "';")
        encryptionID = cursor.fetchone()
        encryptionID = encryptionID[0]
        print(encryptionID)

        #delete all fragment records from database
        cursor.execute("DELETE FROM `filefrag`.`fragments` WHERE (`File_id` = '%s');"%(selectedFileID))
        #delete all encryption records from database
        cursor.execute("DELETE FROM `filefrag`.`encryption` WHERE (`Encryption_id` = '%s');"%(encryptionID))
        #delete all file detail records from database
        cursor.execute("DELETE FROM `filefrag`.`files` WHERE (`File_id` = '%s');"%(selectedFileID))

        con.commit()
        con.close()
        show()
        #Delete fragments from providers
        delete_provider(fragmentLoc_One, fragmentName_One)
        delete_provider(fragmentLoc_Two, fragmentName_Two)
        delete_provider(fragmentLoc_Three, fragmentName_Three)
        delete_provider(fragmentLoc_Four, fragmentName_Four)
        outputLogbox.insert(INSERT, '\n File deleted at: ' + str(dateTimeNow)[:-7]+'\n')

    else:
        infoMessageBox('delete file?', 'No changes made')

#show file details
def show():
    con, cursor = db_con()
    cursor.execute("""SELECT DISTINCT files.file_id, files.filename, files.File_Size, files.Date_Created, `encryption`.Type_
FROM 	filefrag.files 
INNER	JOIN filefrag.fragments ON files.file_id = fragments.file_id 
INNER	JOIN filefrag.`encryption` ON fragments.encryption_id = `encryption`.encryption_id; 
""")
    rows = cursor.fetchall()
    listbox.delete(0, listbox.size())

    fileIDStore = []
    for row in rows:
        thisFileID = row[0]
        thisFilename = row[1]
        thisFilesize = row[2]
        thisFileDateCreated = row[3]
        thisFileEncryptiontype = row[4]

        fileIDStore.append(thisFileID)

        # space between each line in chars
        spacing = '22'
        # create formatting template
        temp = str("{:<" + spacing + "}") * 4
        # create formatted string
        str_cont = temp.format(thisFilename, str(thisFilesize)+'KB', str(thisFileDateCreated)[:-9],  str(thisFileEncryptiontype))
        listbox.insert(listbox.size() + 1, str_cont)

        try:
            listbox.select_set(1) #set highlight selection on the secon item if there is one
        except:
            print('cannot set pre-selected item since there are none')

    return fileIDStore

def show_dropDownlistValues():
    con, cursor = db_con()
    cursor.execute("SELECT Location_Description FROM filefrag.location;")
    location_rows = cursor.fetchall()
    global cloudProviders
    cloudProviders = []
    for location_row in location_rows:
        cloudProviders.append(location_row)

show_dropDownlistValues()


def show_dropDownlistValues():
    con, cursor = db_con()
    cursor.execute("SELECT Location_Description FROM filefrag.location;")
    location_rows = cursor.fetchall()
    global cloudProviders
    cloudProviders = []
    for location_row in location_rows:
        cloudProviders.append(location_row)

show_dropDownlistValues()

def fileOpen():
    root.filename = filedialog.askopenfilename(initialdir=".", title="Select A File", filetypes=[("all files", "*.*")])
    global filename
    global filesize
    global fileDateCreated
    global fileDir
    # split the sub directory part to isolate the filename
    filename = root.filename.split('/')[-1]  #filename
    filesize = os.path.getsize(root.filename)
    filesize = filesize * 0.001  # converting to kilobytes
    filesize = ("%.2f" % filesize)
    print('file size ' + str(filesize))
    fileDateCreated = time.strftime('%Y-%m-%d', time.gmtime(os.path.getmtime(root.filename))) #root.file name instead
    fileDir = root.filename# fileDIR



def upload():
    OTPkey1 = OTPkey1_entry.get()
    OTPkey2 = OTPkey2_entry.get()
    OTPkey3 = OTPkey3_entry.get()
    OTPkey4 = OTPkey4_entry.get()

    con, cursor = db_con()

    location_rows_idsStore = []
    cursor.execute("SELECT Location_id FROM filefrag.location;")
    location_rows_ids = cursor.fetchall()
    for location_rows_id in location_rows_ids:
        location_rows_idsStore.append(location_rows_id[0])

    index_comboBox4 = combo4.current()
    index_comboBox3 = combo3.current()
    index_comboBox2 = combo2.current()
    index_comboBox1 = combo1.current()

    selectedLocationID_four = location_rows_idsStore[index_comboBox4]
    selectedLocationID_three = location_rows_idsStore[index_comboBox3]
    selectedLocationID_two = location_rows_idsStore[index_comboBox2]
    selectedLocationID_one = location_rows_idsStore[index_comboBox1]

    fragUUID1 = uuid.uuid4().hex
    fragUUID2 = uuid.uuid4().hex
    fragUUID3 = uuid.uuid4().hex
    fragUUID4 = uuid.uuid4().hex
    #open file based on AnysubDirectories/file.extention
    with open(fileDir, 'rb') as f:
        content = f.read()
        hexValues = binascii.hexlify(content)

    hexValues = (str(hexValues.decode('utf-8')))

    # initialise a mult-dimensional list
    raid = [[0] * 1 for i in range(4)]
    # remove inital first elements from each sub-list
    raid[0].remove(0)
    raid[1].remove(0)
    raid[2].remove(0)
    raid[3].remove(0)
    # counter for data striping technique
    counter = 0
    for i in hexValues:
        counter += 1
        if (counter == 1):
            raid[0].append(i)
        if (counter == 2):
            raid[1].append(i)
        if (counter == 3):
            raid[2].append(i)
        if (counter == 4):
            raid[3].append(i)
            # reset to 0 when reached 4 iterations
            counter = 0

    # initialise fragment variables
    F1 = ''
    F2 = ''
    F3 = ''
    F4 = ''

    # populate individual fragment variables with correct fragment hex data
    for elemsInRaid in raid[0]:
        F1 = F1 + elemsInRaid

    for elemsInRaid in raid[1]:
        F2 = F2 + elemsInRaid

    for elemsInRaid in raid[2]:
        F3 = F3 + elemsInRaid

    for elemsInRaid in raid[3]:
        F4 = F4 + elemsInRaid

    # -----------Create Fragments-------------------------------------------------------------------------
    idsList = [fragUUID1, fragUUID2, fragUUID3, fragUUID4]

    # check the number of padding bytes
    AmountOfPadding = 0
    print('fragment order: ' + str(idsList))
    file = open(idsList[0], "wb")
    # if length is odd padd a 0
    if not (len(F1) % 2) == 0:
        F1 = F1 + '0'
        AmountOfPadding += 1
    hexDataInput = binascii.a2b_hex(F1)
    file.write(hexDataInput)
    file.close()

    file = open(idsList[1], "wb")
    # if length is odd padd a 0
    if not (len(F2) % 2) == 0:
        F2 = F2 + '0'
        AmountOfPadding += 1
    hexDataInput = binascii.a2b_hex(F2)
    file.write(hexDataInput)
    file.close()

    file = open(idsList[2], "wb")
    # if length is odd padd a 0
    if not (len(F3) % 2) == 0:
        F3 = F3 + '0'
        AmountOfPadding += 1
    hexDataInput = binascii.a2b_hex(F3)
    file.write(hexDataInput)
    file.close()

    file = open(idsList[3], "wb")
    # if length is odd pad a 0
    if not (len(F4) % 2) == 0:
        F4 = F4 + '0'
        AmountOfPadding += 1
    hexDataInput = binascii.a2b_hex(F4)
    file.write(hexDataInput)
    file.close()
    # -----------Encrypt Fragments if user selects encryption option-------------------------------------------------------------------------

    global selectedEncryptionOption
    selectedEncryptionOption = encryptionOptions[combo5.current()]

    # AES OPERATION
    if selectedEncryptionOption == ('AES-256'):

        outputLogbox.insert(INSERT, '\nSelected AES-256 option at: ' + str(dateTimeNow)[:-7] + '\n')
        print('AES-256 encryption applied')

        encryptAES(getKey(RandomKeyString), fragUUID4)
        encryptAES(getKey(RandomKeyString), fragUUID3)
        encryptAES(getKey(RandomKeyString), fragUUID2)
        encryptAES(getKey(RandomKeyString), fragUUID1)

        upload_provider(combo4.get(), fragUUID4 + ('.e'))
        upload_provider(combo3.get(), fragUUID3 + ('.e'))
        upload_provider(combo2.get(), fragUUID2 + ('.e'))
        upload_provider(combo1.get(), fragUUID1 + ('.e'))

        encryptionID = uuid.uuid4().hex

        # Insert encryption ID into encryptiont table

        # Insert Data and AES key into database
        sqlFormula = ("""SET @uuid = UUID();
               insert into filefrag.encryption(Encryption_id, type_, Key1_)
               VALUES('%s', '%s', '%s');
               insert into filefrag.files (file_id, filename, File_size, Date_Created, AmountOfPadding)
               VALUES
               (@UUID, '%s', '%s', '%s', '%s');
               insert into filefrag.fragments (Fragment_id, Index_, File_id, Location_id, Encryption_id)
               VALUES
               ('%s', '1', @UUID, '%s', '%s'), 
               ('%s', '2', @UUID, '%s', '%s'), 
               ('%s', '3', @UUID, '%s', '%s'), 
               ('%s', '4', @UUID, '%s', '%s'); """ %
                      (encryptionID, selectedEncryptionOption, RandomKeyString, filename, filesize, fileDateCreated, AmountOfPadding, fragUUID1,
                       selectedLocationID_one, encryptionID,
                       fragUUID2, selectedLocationID_two, encryptionID,
                       fragUUID3, selectedLocationID_three, encryptionID,
                       fragUUID4, selectedLocationID_four, encryptionID))

        for _ in cursor.execute(sqlFormula, multi=True): pass
        con.commit()
        con.close()
        show()
        infoMessageBox('CDCP Status', 'Uploaded Successfully')
        outputLogbox.insert(INSERT, '\nUploaded file Successfully at: ' + str(dateTimeNow)[:-7] + '\n')
        os.remove(fragUUID1 + ('.e'))
        os.remove(fragUUID2 + ('.e'))
        os.remove(fragUUID3 + ('.e'))
        os.remove(fragUUID4 + ('.e'))

        # No ENCRYPTION OPERATION
    if selectedEncryptionOption == ('None'):
        outputLogbox.insert(INSERT, '\nSelected No encryption option at: ' + str(dateTimeNow)[:-7] + '\n')
        print('no encryption applied')
        upload_provider(combo4.get(), fragUUID4)
        upload_provider(combo3.get(), fragUUID3)
        upload_provider(combo2.get(), fragUUID2)
        upload_provider(combo1.get(), fragUUID1)

        encryptionID = uuid.uuid4().hex

        sqlFormula = ("""SET @uuid = UUID();
                 insert into filefrag.encryption(Encryption_id, type_)
                 VALUES('%s', '%s');
                 insert into filefrag.files (file_id, filename, File_size, Date_Created, AmountOfPadding)
                 VALUES
                 (@UUID, '%s', '%s', '%s', '%s');
                 insert into filefrag.fragments (Fragment_id, Index_, File_id, Location_id, Encryption_id)
                 VALUES
                 ('%s', '1', @UUID, '%s', '%s'), 
                 ('%s', '2', @UUID, '%s', '%s'), 
                 ('%s', '3', @UUID, '%s', '%s'), 
                 ('%s', '4', @UUID, '%s', '%s'); """ %
                      (encryptionID, selectedEncryptionOption, filename, filesize, fileDateCreated, AmountOfPadding, fragUUID1,
                       selectedLocationID_one, encryptionID,
                       fragUUID2, selectedLocationID_two, encryptionID,
                       fragUUID3, selectedLocationID_three, encryptionID,
                       fragUUID4, selectedLocationID_four, encryptionID))

        for _ in cursor.execute(sqlFormula, multi=True): pass
        con.commit()
        con.close()
        show()
        infoMessageBox('CDCP Status', 'Uploaded Successfully')
        outputLogbox.insert(INSERT, '\nUploaded file Successfully at: ' + str(dateTimeNow)[:-7] + '\n')

        # OTP OPERATION
    if selectedEncryptionOption == ('OTP'):
        if float(filesize) >= 1996:  # if file is larger than 1996 bytes then do not OTP encrypt
            infoMessageBox('CDCP Status', 'Warning cannot use OTP on files larger than 1996 bytes')
        else:
            outputLogbox.insert(INSERT, '\nSelected OTP option at: ' + str(dateTimeNow)[:-7] + '\n')
            OTPencryption(fragUUID4, OTPkey4)
            OTPencryption(fragUUID3, OTPkey3)
            OTPencryption(fragUUID2, OTPkey2)
            OTPencryption(fragUUID1, OTPkey1)

            upload_provider(combo4.get(), fragUUID4)
            upload_provider(combo3.get(), fragUUID3)
            upload_provider(combo2.get(), fragUUID2)
            upload_provider(combo1.get(), fragUUID1)

            encryptionID = uuid.uuid4().hex  # define encryption ID for insertion into database

            # Insert Data and OTP keys into database
            sqlFormula = ("""SET @uuid = UUID();
                             insert into filefrag.encryption(Encryption_id, type_, Key1_, Key2_, Key3_, Key4_)
                             VALUES('%s', '%s', '%s', '%s', '%s', '%s');
                             insert into filefrag.files (file_id, filename, File_size, Date_Created, AmountOfPadding)
                             VALUES
                             (@UUID, '%s', '%s', '%s', '%s');
                             insert into filefrag.fragments (Fragment_id, Index_, File_id, Location_id, Encryption_id)
                             VALUES
                             ('%s', '1', @UUID, '%s', '%s'), 
                             ('%s', '2', @UUID, '%s', '%s'), 
                             ('%s', '3', @UUID, '%s', '%s'), 
                             ('%s', '4', @UUID, '%s', '%s'); """ %
                          (encryptionID, selectedEncryptionOption, OTPkey1, OTPkey2, OTPkey3, OTPkey4, filename, filesize, fileDateCreated, AmountOfPadding,
                           fragUUID1,
                           selectedLocationID_one, encryptionID,
                           fragUUID2, selectedLocationID_two, encryptionID,
                           fragUUID3, selectedLocationID_three, encryptionID,
                           fragUUID4, selectedLocationID_four, encryptionID))

            for _ in cursor.execute(sqlFormula, multi=True): pass
            con.commit()
            con.close()
            show()
            infoMessageBox('CDCP Status', 'Uploaded Successfully')
            outputLogbox.insert(INSERT, '\nUploaded file Successfully at: ' + str(dateTimeNow)[:-7] + '\n')
    # now delete all the fragments to save memory
    try:
        os.remove(fragUUID1)
        os.remove(fragUUID2)
        os.remove(fragUUID3)
        os.remove(fragUUID4)
    except:
        print('fragments do not exist')

def clearlogWindow():
    outputLogbox.delete('1.0', END)

def clearOTPfields():
    OTPkey1_entry.delete(0, END)
    OTPkey2_entry.delete(0, END)
    OTPkey3_entry.delete(0, END)
    OTPkey4_entry.delete(0, END)

def openManual():
    try:
        os.startfile(r'additional_Files\userManual.pdf')
    except:
        infoMessageBox('error message', 'Could not open PDF viewer for user manual. Please ensure any pdf reader is installed')


def clearRenamingField():
    if len(renameFile_entry.get()) == 0:
        infoMessageBox('error message', 'there is nothing to clear')
    else:
        renameFile_entry.delete(0, END)
# --------------End Of...Functions--------------------
# --------------Design of System----------------------

# define window size and title
root = tk.ThemedTk()
root.get_themes()
root.set_theme("black")  # equilux
root.geometry("1020x800")
root.title("CDCP")
root.iconbitmap(r'additional_Files\icon.ico')
# -----New window for entropy generator-----------------
window = None
progress = None
style = None
entry = None
#=============================================================

#EntropyThreshold = 191
EntropyThreshold = 100
# convert list of X Y to SHA
def get_sha_from_list(myList):
    OutputValuesinHex = ''.join(map(str, chain.from_iterable(myList)))
    result = hashlib.sha512(OutputValuesinHex.encode())
    return result.hexdigest()

# set text to Text Box
def set_text(text):
    entry.delete("1.0", END)
    entry.insert(END, text)
    entry.config(fg='lawn green')

RandomKey = []
myList = []
prev_x = 0
prev_y = 0

def monitoring():
    global myList
    global prev_y
    global prev_x
    global RandomKeyString
    #try to track x and y coordinates
    try:
        x, y = pyautogui.position()
        x, y = int(str(x).rjust(4)), int(str(y).rjust(4))

        if len(myList) < (EntropyThreshold):

            new_x, new_y = int(str(x).rjust(4)), int(str(y).rjust(4))
            if new_x > 0 and new_y > 0:
                if new_x != prev_x and new_y != prev_y:
                    prev_x = new_x
                    prev_y = new_y
                    # print((new_x, new_y))
                    percent = int((len(myList) / (EntropyThreshold)) * 100) + int(len(myList) % (EntropyThreshold) > 0)
                    # append first x axis and then y axis
                    myList.append((new_x, new_y))
                    SHAData = get_sha_from_list(myList)
                    set_text(SHAData)
                    set_value_to_pb(percent)
                    if (percent == 97):  # once enough entropy has been generated apply the sha-512 >>
                        RandomKey.append(SHAData)
                    set_value_to_pb(percent)
                    if (percent == 98):  # once enough entropy has been generated apply the sha-512 >>
                        RandomKey.append(SHAData)
                    set_value_to_pb(percent)
                    if (percent == 99):  # once enough entropy has been generated apply the sha-512 >>
                        RandomKey.append(SHAData)
                    if (percent == 100):  # once enough entropy has been generated apply the sha-512 >>
                        RandomKey.append(SHAData)
                        RandomKeyString = (RandomKey[0] + RandomKey[1] + RandomKey[2] + RandomKey[3][:-12])  # cut last 12 bytes since database cannot handle it
                        outputLogbox.insert(INSERT, '\nKey Generated: ' + RandomKeyString + '\n')
                        outputLogbox.insert(INSERT, '\n')
                        RandomKeyString = ''
                        print('SHOW CURRENT:'+RandomKeyString)
            # recursive  caller for updating the GUI in the main thread of window
            window.after(100, lambda: monitoring())
        else:
            messagebox.showinfo('CDCP!', 'Key generated')
            myList.clear() #clear the collected y and x axis from list
            RandomKey.clear() #clear the random key
    except KeyboardInterrupt:
        print('\n')

def settings():
    global entropyThresholdEntry
    global hostEntry
    global userEntry
    global passwordEntry
    global localDownloadLocation_Entry
    Settingswindow = Toplevel(root)
    Settingswindow.geometry("540x300")
    Settingswindow.configure(bg=_from_rgb((61, 61, 63)))
    Settingswindow.iconbitmap(r'additional_Files\icon.ico')
    #settings window configs
    Label(Settingswindow, text="Settings", font=(None, 20), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='10', y='10')
    hostEntry = Entry(Settingswindow, width=40)
    hostEntry.place(x=10, y=80)
    Label(Settingswindow, text="Hostname settings", font=(None, 8), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='10', y='60')
    hostEntry.insert(INSERT, SQLhost)

    Label(Settingswindow, text="Username settings", font=(None, 8), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='10', y='100')
    userEntry = Entry(Settingswindow, width=40)
    userEntry.place(x=10, y=120)
    userEntry.insert(INSERT, SQLuser)
    Label(Settingswindow, text="Password settings", font=(None, 8), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='10', y='140')

    passwordEntry = Entry(Settingswindow, show="*", width=40)
    passwordEntry.place(x=10, y=160)
    passwordEntry.insert(INSERT, SQLpassword)
    Label(Settingswindow, text="Entropy Threshold settings", font=(None, 8), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='10', y='190')
    entropyThresholdEntry = Entry(Settingswindow, width=10)

    entropyThresholdEntry.place(x=10, y=215)
    entropyThresholdEntry.insert(INSERT, EntropyThreshold)
    Label(Settingswindow, text="Download Location", font=(None, 8), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='270', y='190')
    localDownloadLocation_Entry = Entry(Settingswindow, width=40)

    localDownloadLocation_Entry.place(x=270, y=215)
    localDownloadLocation_Entry.insert(INSERT, localDownloadLocation)

    applySettings_btn = ttk.Button(Settingswindow, text="    Apply", width=10, command=InitialSettings)
    applySettings_btn.pack()
    applySettings_btn.place(x=10, y=260)

# set value to progress bar and progress bar text value
def set_value_to_pb(value):
    progress['value'] = value

def create_window():
    global window
    global progress
    global style
    global entry

    window = Toplevel(root)
    window.geometry("600x600")
    window.configure(bg=_from_rgb((61, 61, 63)))
    window.iconbitmap(r'additional_Files\icon.ico')
    Label(window, text="Move the mouse to generate a key", font=(None, 15), fg='light gray', bg=_from_rgb((61, 61, 63))).place(x='50', y='100')

    #entry box of new window of for entropy key generator
    entry = Text(window)
    entry.place(x='50', y='200', height=50, width=500)
    entry.config(background='gray27')

    progress = ttk.Progressbar(window, style='text.Horizontal.TProgressbar', length=500,
                               maximum=100, value=0)
    progress.place(x='50', y='400')
    b = Button(window, text="Start", command=monitoring)
    b.place(x='50', y='500', height=40, width=80)

# ------------------------------------------------
# define rgb colour for background colour
def _from_rgb(rgb):
    return "#%02x%02x%02x" % rgb

# apply background colour
root.configure(bg=_from_rgb((61, 61, 63)))

# ELEMENTS INSIDE WINDOW---------------------------------
listbox = Listbox(root, background='gray27', fg="light grey", selectbackground="dark turquoise", highlightcolor="black", bd=0)
listbox.pack(side ='left', fill='y')

frame = Frame(root)
frame.place(x = 1000, y = 20)

listbox.place(x=360, y=20)
listbox.config(width=79, height=19, font=('Monaco', 10), activestyle="none")

download_btn = ttk.Button(root, text="                  Download File", width=30, command=QueryAndDownloadFile)
download_btn.pack()
download_btn.place(x=359, y=355)

delete_btn = ttk.Button(root, text="                  Delete file", width=30, command=deleteRecord)
delete_btn.pack()
delete_btn.place(x=359, y=390)

rename_btn = ttk.Button(root, text="                  Rename file", width=30, command=renameFile)
rename_btn.pack()
rename_btn.place(x=580, y=355)

renameFile_entry = Entry(root, width=33)
renameFile_entry.pack()
renameFile_entry.place(x=790, y=357)

Clearlogs_btn = ttk.Button(root, text="                  Clear Logs", width=30, command=clearlogWindow)
Clearlogs_btn.pack()
Clearlogs_btn.place(x=580, y=390)

settings_btn = ttk.Button(root, text="                             Settings", width=40, command=settings)
settings_btn.pack()
settings_btn.place(x=30, y=600)

userManual_btn = ttk.Button(root, text="                           User Manual", width=40, command=openManual)
userManual_btn.pack()
userManual_btn.place(x=30, y=630)

exit_btn = ttk.Button(root, text="                                  Exit", width=40, command=root.destroy)
exit_btn.pack()
exit_btn.place(x=30, y=660)

outputLogbox = Text(root, width=90, height=19, background='gray27', fg="dark turquoise",
                    selectbackground="dark turquoise", highlightcolor="black", font=('Arial', 10))
outputLogbox.pack()
outputLogbox.place(x=360, y=430)

#log box window-----------------------------------------------------------------------------------------
outputLogbox.insert(INSERT, """\nLOGGING: """ + str(dateTimeNow)[:-15] + """................
CDCP Initilised --->
Fetched file information --->
Fetched file CSP locations --->
Ready for use --->

Made by Andre Grey-Allen
""")

openFile_btn = ttk.Button(root, text="           Select File", width=20, command=fileOpen)
openFile_btn.pack()
openFile_btn.place(x=30, y=340)

# Dropdown list for Provider selection
combo1 = Combobox(root, state="readonly", values=cloudProviders, width=20)
combo1.set("Provider #1")
combo1.pack()
combo1.place(x=30, y=210)  # y is horizontal positioning x is vertical positioning

combo2 = Combobox(root, state="readonly", values=cloudProviders, width=20)
combo2.set("Provider #2")
combo2.pack()
combo2.place(x=180, y=210)

combo3 = Combobox(root, state="readonly", values=cloudProviders, width=20)
combo3.set("Provider #3")
combo3.pack()
combo3.place(x=30, y=245)

combo4 = Combobox(root, state="readonly", values=cloudProviders, width=20)
combo4.set("Provider #4")
combo4.pack()
combo4.place(x=180, y=245)

# upload button for file
upload_btn = ttk.Button(root, text="           Upload", width=20, command=upload)
upload_btn.pack()
upload_btn.place(x=30, y=380)

# upload button for file
clearRename_btn = ttk.Button(root, text="           Clear Renaming Field", width=31, command=clearRenamingField)
clearRename_btn.pack()
clearRename_btn.place(x=789, y=390)

OTPkey1_entry = Entry(root)
OTPkey1_entry.pack()
OTPkey1_entry.place(x=30, y=440)

OTPkey2_entry = Entry(root)
OTPkey2_entry.pack()
OTPkey2_entry.place(x=180, y=440)

OTPkey3_entry = Entry(root)
OTPkey3_entry.pack()
OTPkey3_entry.place(x=30, y=470)

OTPkey4_entry = Entry(root)
OTPkey4_entry.pack()
OTPkey4_entry.place(x=180, y=470)

OTPfieldClearButton = ttk.Button(root, text="                                  Clear Keys", width=43, command=clearOTPfields)
OTPfieldClearButton.pack()
OTPfieldClearButton.place(x=29, y=500)

root.option_add("*TCombobox*Listbox*Background", 'gray')
root.option_add("*TCombobox*Listbox*foreground", 'light gray')
root.option_add("*TCombobox*Listbox*selectBackground", 'dark turquoise')
""" 
combostyle = ttk.Style()
combostyle.theme_create('combostyle', parent='alt',
                         settings = {'TCombobox':
                                     {'configure':
                                      {'selectbackground': 'dark turquoise',
                                       'fieldbackground': 'gray',
                                       'background': 'gray',
                                       'foreground': 'light gray'
                                       }}}
                         )

combostyle.theme_use('combostyle')
"""
# Encryption section ---------------------------------------------------------------------------------
# values for encryption options
encryptionOptions = ['None', 'AES-256', 'OTP']

# Dropdown list for encryption option
combo5 = Combobox(root, state="readonly", values=encryptionOptions, width=20)
combo5.set("None")
combo5.pack()
combo5.place(x=30, y=300)

EntropyKeygen_btn = ttk.Button(root, text="Entropy Key Generator", width=20, command=create_window)
EntropyKeygen_btn.pack()
EntropyKeygen_btn.place(x=180, y=300)
# END OF......Encryption section --------------------------------------------------------------------

smallLogo = PhotoImage(file="additional_Files\cdcpLogo.png")
smallLogo = smallLogo.subsample(2, 2)
smallLabel = Label(root,image=smallLogo, height=200, borderwidth=0, highlightthickness=0)
smallLabel.pack()
smallLabel.place(x=80, y=-10)

ListboxLabel = Label(root, text="Filename__________________________Filesize____________________________Date Created_____________________Encryption Type", fg='dark turquoise', bg=_from_rgb((61, 61, 63)))
ListboxLabel.pack()
ListboxLabel.place(x=358, y=1)

EncryptionLabel = Label(root, text="Encryption Selection", fg='light gray', bg=_from_rgb((61, 61, 63)))
EncryptionLabel.pack()
EncryptionLabel.place(x=30, y=278)

OTPLabel = Label(root, text="__________________OTP Keys Specifier________________", fg='light gray', bg=_from_rgb((61, 61, 63)))
OTPLabel.pack()
OTPLabel.place(x=30, y=417)
# --------------END OF...Design of System------------------------------------------------------------
show()

root.mainloop()
