from cgitb import text
from ctypes.wintypes import SIZE
import tkinter as tk
from tkinter  import Button, Entry, Label, StringVar, ttk
from tkinter import filedialog
from tkinter import messagebox
from tkinter import font


root=tk.Tk()
root.title('SHA256 Implementation : Cryptography Course Final Project')

root.geometry('1200x500')
root.configure(bg='#3a7e7d')


StringLabel=tk.Label(root,text='Input Value',font=10)
ResultLabel=tk.Label(root,text="Hashed Result",font=10)


Result =  tk.StringVar()
val = tk.StringVar()
InputData = tk.StringVar()
StringEntry=Entry(root,textvariable=val,font=10)
ResultEntry=Entry(root,textvariable=Result,font=10)


StringLabel.grid(row=0,column=0,padx=46,
               pady=60,
               ipady=10)
StringEntry.grid(row=0,column=1,padx=10,
               pady=10,
               ipadx=250,
               ipady=10)
ResultLabel.grid(row=1,column=0)

ResultEntry.grid(row=1,column=1,padx=26,
               pady=10,
               ipadx=250,
               ipady=60)

def browseFiles():
    filename = filedialog.askopenfilename(initialdir = "/",
                                          title = "Select a File",
                                          filetypes = (("Text files",
                                                        "*.txt*"),
                                                       ("all files",
                                                        "*.*")))
    InputData.set(filename)
    val.set(("File path: "+filename))

button_browse = Button(root,font=10,
                        text = " or Browse Files",
                        command = browseFiles)

#SHA-256 algorithm Implementation



def computeHash(msg) :
    # Initial Hash value
    H=[0x6a09e667,
    0xbb67ae85,
    0x3c6ef172,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19]

    constant_k = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]
    
    if type(msg)==str:
        msg = bytearray(msg, 'utf-8')
    elif type(msg)== bytes:
        msg = bytearray(msg)
    else:
        raise TypeError

    # Padding
    length = len(msg) * 8 
    msg.append(0x80)
    while (len(msg) * 8 + 64) % 512 != 0:
        msg.append(0x00)

    msg += length.to_bytes(8, 'big') 

    

    Blk = [msg[i:i+64]  for i in range(0, len(msg), 64)] 

    

    # SHA-256 calculation
    for msgBlock in Blk:
        # Prepare message schedule
        msgSchedule = []
        for i in range(0, 64):
            if i <= 15:
               
                msgSchedule.append(bytes(msgBlock[i*4:(i*4)+4]))
            else:
                T1 = sig1(int.from_bytes(msgSchedule[i-2], 'big'))
                T2 = int.from_bytes(msgSchedule[i-7], 'big')
                T3 = sig0(int.from_bytes(msgSchedule[i-15], 'big'))
                T4 = int.from_bytes(msgSchedule[i-16], 'big')

                # append a 4-byte byte object
                schedule = ((T1 + T2 + T3 + T4) % 2**32).to_bytes(4, 'big')
                msgSchedule.append(schedule)

        

        # Initialize  variables
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]

        
        for t in range(64):
            t1 = ((h + uppsig1(e) + Ch(e, f, g) + constant_k[t] +
                   int.from_bytes(msgSchedule[t], 'big')) % pow(2,32))

            t2 = (uppsig0(a) + Maj(a, b, c)) % pow(2,32)

            h = g
            g = f
            f = e
            e = (d + t1) % pow(2,32)
            d = c
            c = b
            b = a
            a = (t1 + t2) % pow(2,32)

        # Compute intermediate hash value
        H[0] = (H[0] + a) % pow(2,32)
        H[1] = (H[1] + b) % pow(2,32)
        H[2] = (H[2] + c) % pow(2,32)
        H[3] = (H[3] + d) % pow(2,32)
        H[4] = (H[4] + e) % pow(2,32)
        H[5] = (H[5] + f) % pow(2,32)
        H[6] = (H[6] + g) % pow(2,32)
        H[7] = (H[7] + h) % pow(2,32)

        result=Output(H).hex()
    return result
def ToByte(hex):
  return hex.to_bytes(4, 'big')
def Output(hexa):
    return (ToByte(hexa[0]) +  ToByte(hexa[1])  + ToByte(hexa[2])  + ToByte(hexa[3])  +
          ToByte(hexa[4])  + ToByte(hexa[5])  + ToByte(hexa[6])  + ToByte(hexa[7]) )

def sig0(msg):
    return (ROTR(msg, 7) ^ ROTR(msg, 18) ^ (msg >> 3))

def sig1(msg):
    return (ROTR(msg, 17) ^ ROTR(msg, 19) ^ (msg >> 10))

def uppsig0(msg):
    return (ROTR(msg, 2) ^  ROTR(msg, 13) ^ ROTR(msg, 22))

def uppsig1(msg):
    return (ROTR(msg, 6) ^ ROTR(msg, 11) ^ ROTR(msg, 25))

def Ch(a,b,c):
    return (a & b) ^ (~a & c)


def Maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)


# rotate right
def ROTR(msg, shift, size: int=32):
   
    return (msg >> shift) | (msg << size - shift)
def button_clicked():
    
    if  len(val.get())>0:
        b=val.get()
    
        if b.__contains__('path'):
            file=open(InputData.get(),encoding='utf-8')
            print(file)
            Result.set(computeHash(file.read()))
            
        else:
            Result.set(computeHash(val.get()))
    else:
        
        messagebox.showwarning("Warning","Please type or browse data to Hash")
def reset():
    val.set('')
    Result.set('')
    
    
sub_btn=Button(root,text='Generate Result',command=button_clicked,font=10)
sub_btn.grid(row=33,column=1)
resetbtn=Button(root,text = "Reset",command=reset,font=10)
resetbtn.grid(row=33,column=2)
button_browse.grid(row=0,column=2)
try:
    from ctypes import windll

    windll.shcore.SetProcessDpiAwareness(1)
finally:
    root.mainloop()



