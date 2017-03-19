#coding with UTF-8
from Tkinter import *
import random
import tkMessageBox
import hashlib

def fastExpMod(b, e, m):
    """
    e = e0*(2^0) + e1*(2^1) + e2*(2^2) + ... + en * (2^n)

    b^e = b^(e0*(2^0) + e1*(2^1) + e2*(2^2) + ... + en * (2^n))
        = b^(e0*(2^0)) * b^(e1*(2^1)) * b^(e2*(2^2)) * ... * b^(en*(2^n)) 

    b^e mod m = ((b^(e0*(2^0)) mod m) * (b^(e1*(2^1)) mod m) * (b^(e2*(2^2)) mod m) * ... * (b^(en*(2^n)) mod m) mod m
    """
    result = 1
    while e != 0:
        if (e&1) == 1:
            # ei = 1, then mul
            result = (result * b) % m
        e >>= 1
        # b, b^2, b^4, b^8, ... , b^(2^n)
        b = (b*b) % m
    return result

def primeTest(n):
    q = n - 1
    k = 0
    #Find k, q, satisfied 2^k * q = n - 1
    while q % 2 == 0:
        k += 1
        q /= 2
    a = random.randint(2, n-2)
    #If a^q mod n= 1, n maybe is a prime number
    if fastExpMod(a, q, n) == 1:
        return "inconclusive"
    #If there exists j satisfy a ^ ((2 ^ j) * q) mod n == n-1, n maybe is a prime number
    for j in range(0, k):
        if fastExpMod(a, (2**j)*q, n) == n - 1:
            return "inconclusive"
    #a is not a prime number
    return "composite"

def findPrime(halfkeyLength):
    while True:
        #Select a random number n 
        n = random.randint(0, 1<<halfkeyLength)
        if n % 2 != 0:
            found = True
            #If n satisfy primeTest 10 times, then n should be a prime number
            for i in range(0, 10):
                if primeTest(n) == "composite":
                    found = False
                    break
            if found:
                return n

def extendedGCD(a, b):
    #a*xi + b*yi = ri
    if b == 0:
        return (1, 0, a)
    #a*x1 + b*y1 = a
    x1 = 1
    y1 = 0
    #a*x2 + b*y2 = b
    x2 = 0
    y2 = 1
    while b != 0:
        q = a / b
        #ri = r(i-2) % r(i-1)
        r = a % b
        a = b
        b = r
        #xi = x(i-2) - q*x(i-1)
        x = x1 - q*x2
        x1 = x2
        x2 = x
        #yi = y(i-2) - q*y(i-1)
        y = y1 - q*y2
        y1 = y2
        y2 = y
    return(x1, y1, a)

def selectE(fn, halfkeyLength):
    while True:
        #e and fn are relatively prime
        e = random.randint(0, 1<<halfkeyLength)
        (x, y, r) = extendedGCD(e, fn)
        if r == 1:
            return e

def computeD(fn, e):
    (x, y, r) = extendedGCD(fn, e)
    #y maybe < 0, so convert it 
    if y < 0:
        return fn + y
    return y

def keyGeneration(keyLength):
    #generate public key and private key
    p = findPrime(keyLength/2)
    q = findPrime(keyLength/2)
    n = p * q
    fn = (p-1) * (q-1)
    e = selectE(fn, keyLength/2)
    d = computeD(fn, e)
    return (n, e, d)

def encryption(M, e, n):
    #RSA C = M^e mod n
    return fastExpMod(M, e, n)

def decryption(C, d, n):
    #RSA M = C^d mod n
    return fastExpMod(C, d, n)

class App(Tk):

	def __init__(self):
		Tk.__init__(self)
		self.Initial()

	def Initial(self):  
		m = Menu(self)
		self.config(menu=m)
		modemenu = Menu(m)
		m.add_cascade(label ="Mode",menu=modemenu)
		modemenu.add_command(label = "Text Encryption")
		modemenu.add_command(label = "Digital Signature",command=self.DiS)
		modemenu.add_separator()
		modemenu.add_command(label = "Exit",command = self.callback)
		helpmenu = Menu(m)
		m.add_cascade(label="Help",menu=helpmenu)
		helpmenu.add_command(label = "About...")
		Label(self,text="Choose a file:").grid(row=1,column=0,sticky=W+E)
		self.filename = StringVar()
		self.filename = Entry(self)
		self.filename.grid(row=1,column=1,columnspan=5,sticky=W+E)
		#self.btest=Button(self,text="OK",command=self.showfile)
		#self.btest.grid(row=1,column=8)
		Button(self,text="encrypt",command=self.encrypt).grid(row=1,column=6)
		Button(self,text="decrypt",command=self.decrypt).grid(row=1,column=7)
		Label(self,text="Or you can input:").grid(row=2,column=0,sticky=W+E)
		self.text=Text(self)
		self.text.grid(row=3,column=1,rowspan=1,columnspan=4)
		Button(self,text="encrypt",command=self.text_encry).grid(row=3,column=6,sticky=N)
		Button(self,text="decrypt",command=self.text_decry).grid(row=3,column=7,sticky=N)

	def callback(self):
		self.destroy()
		
	def encrypt(self):
		a= tkMessageBox.askquestion("tishi","Do you want to encrypt?")
		if a=='yes' :
			self.encry = Tk()
			self.encry.title("Encryption")
			Label(self.encry,text="Input the key or generate a pair of key:").grid(row=0,column=0)
			Label(self.encry,text="Private key:").grid(row=1,column=0)
			self.key1 = Entry(self.encry)
			self.key1.grid(row=1,column=1,sticky=W)
			Label(self.encry,text="Private key:").grid(row=1,column=2)
			self.key2 = Entry(self.encry)
			self.key2.grid(row=1,column=3,sticky=W)
			Button(self.encry,text="OK",command=self.cal).grid(row=1,column=4)
			Button(self.encry,text="Generate a pair of key",command=self.gene).grid(row=1,column=5)
			Label(self.encry,text = "The encrypted file position :").grid(row=2,column=0)
			self.filename1=Entry(self.encry)
			self.filename1.grid(row=2,column=1)
			Button(self.encry,text="Start",command=self.file_encry).grid(row=2,column=2)

	def file_handle1(self):
		try:
			f = open(self.filename.get(),"r")
			text = f.read()
			text = str(text)
			self.list1 = []
			for i in range(0,len(text)):
				self.list1.append(ord(text[i]))
			print self.list1
			#for a in list1:
				#list2.append(encryption(c,public_key,self.N))
			#print list1
		except:
			tkMessageBox.showerror("Error","Not found,check the input")
			self.encry.destroy()

	def cal(self):
		self.e=int(self.key1.get())
		self.n=int(self.key2.get())
		self.file_handle1()
		for M in self.list1:
			if M > self.n:
				tkMessageBox.showerror("Error","Please input correct Key,N must be larger than %d"%max(self.list1))
				self.key1.select_clear()
				self.key2.select_clear()
				break

	def gene(self):
		self.file_handle1()
		(self.n, self.e, self.d)=keyGeneration(14)
		while self.n < max(self.list1):
			(self.n, self.e, self.d)=keyGeneration(14)
		tkMessageBox.showinfo("Your Key","Please remember :\n Your public key is %d.\nYour private key is %d.\n N is %d."%(self.d,self.e,self.n))

	def file_encry(self):
		self.list2=[]
		for a in self.list1 :
			c = encryption(a,self.e,self.n)
			self.list2.append(c)
		self.list3=[]
		for b in self.list2:
			self.list3.append(unichr(b))
		fname = self.filename1.get()
		f = open(fname,"w")
		for i in self.list3:
			f.write(i.encode('utf8'))
		tkMessageBox.showinfo("tishi","Encryption Finished!")
		self.encry.destroy()

	def decrypt(self):
		a= tkMessageBox.askquestion("tishi","Do you want to decrypt?")
		if a=='yes' :
			self.decry = Tk()
			self.decry.title("Decryption")
			Label(self.decry,text="Input the key :").grid(row=0,column=0)
			Label(self.decry,text="Public key:").grid(row=1,column=0)
			self.key3 = Entry(self.decry)
			self.key3.grid(row=1,column=1,sticky=W)
			Label(self.decry,text="N:").grid(row=1,column=2)
			self.key4 = Entry(self.decry)
			self.key4.grid(row=1,column=3,sticky=W)
			Button(self.decry,text="OK",command=self.cal2).grid(row=1,column=4)
			Label(self.decry,text = "The decrypted file position :").grid(row=2,column=0)
			self.filename2=Entry(self.decry)
			self.filename2.grid(row=2,column=1)
			Button(self.decry,text="Start",command=self.file_decry).grid(row=2,column=2)

	def cal2(self):
		self.d=int(self.key3.get())
		self.n=int(self.key4.get())
		self.file_handle2()

	def file_handle2(self):
		try:
			f = open(self.filename.get(),"r")
			text = f.read()
			text = str(text)
			text = text.decode('utf8')
			#print text
			self.list1 = []
			for i in range(0,len(text)):
				self.list1.append(ord(text[i]))
		except:
			tkMessageBox.showerror("Error","Not found,check the input")
			self.decry.destroy()	

	def file_decry(self):
		self.list2=[]
		for a in self.list1 :
			c = decryption(a,self.d,self.n)
			self.list2.append(c)
		#print self.list2
		self.list3=[]
		for b in self.list2:
			self.list3.append(chr(b))
		fname = self.filename2.get()
		f = open(fname,"w")
		for i in self.list3:
			f.write(i)
		tkMessageBox.showinfo("tishi","Decryption Finished!")
		self.decry.destroy()

	def text_encry(self):
		a= tkMessageBox.askquestion("tishi","Do you want to encrypt?")
		if a=='yes' :
			self.tencry = Tk()
			self.tencry.title("Encryption")
			Label(self.tencry,text="Input the key or generate a pair of key:").grid(row=0,column=0)
			Label(self.tencry,text="Private key:").grid(row=1,column=0)
			self.keya = Entry(self.tencry)
			self.keya.grid(row=1,column=1,sticky=W)
			Label(self.tencry,text="N :").grid(row=1,column=2)
			self.keyb = Entry(self.tencry)
			self.keyb.grid(row=1,column=3,sticky=W)
			Button(self.tencry,text="OK",command=self.cal3).grid(row=1,column=4)
			Button(self.tencry,text="Generate a pair of key",command=self.gene1).grid(row=1,column=5)
			Label(self.tencry,text = "The encrypted text will be shown in the initial text window.").grid(row=2,column=0)
			Button(self.tencry,text="Start",command=self.text_en).grid(row=2,column=2)

	def cal3(self):
		self.e=int(self.keya.get())
		self.n=int(self.keyb.get())
		self.list1=[]
		for a in self.text.get('0.0',END):
			self.list1.append(ord(a))
		self.list1.pop()            
		for M in self.list1:
			if M > self.n:
				tkMessageBox.showerror("Error","Please input correct Key,N must be larger than %d"%max(self.list1))
				self.key1.select_clear()
				self.key2.select_clear()
				break
	def gene1(self):
		self.list1=[]
		for a in self.text.get('0.0',END):
			self.list1.append(ord(a))
		self.list1.pop()
		(self.n, self.e, self.d)=keyGeneration(16)
		while self.n < max(self.list1):
			(self.n, self.e, self.d)=keyGeneration(14)
		tkMessageBox.showinfo("Your Key","Please remember :\n Your public key is %d.\nYour private key is %d.\n N is %d."%(self.d,self.e,self.n))

	def text_en(self):
		self.list2=[]
		for a in self.list1 :
			c = encryption(a,self.e,self.n)
			self.list2.append(c)
		self.list3=[]
		for b in self.list2:
			self.list3.append(unichr(b))
		self.list4=[]
		for i in self.list3:
			self.list4.append(i.encode('utf8'))
		self.text.delete(0.0,10.0)
		for k in self.list4:
			self.text.insert(END,k)
			#print k
		tkMessageBox.showinfo("tishi","Encryption Finished!")
		self.tencry.destroy()

	def text_decry(self):
		a= tkMessageBox.askquestion("tishi","Do you want to decrypt?")
		if a=='yes' :
			self.tdecry = Tk()
			self.tdecry.title("Decryption")
			Label(self.tdecry,text="Input the key :").grid(row=0,column=0)
			Label(self.tdecry,text="Public key:").grid(row=1,column=0)
			self.keya = Entry(self.tdecry)
			Label(self.tdecry,text="N:").grid(row=1,column=2)
			self.keya.grid(row=1,column=1,sticky=W)
			self.keyb = Entry(self.tdecry)
			self.keyb.grid(row=1,column=3,sticky=W)
			Button(self.tdecry,text="OK",command=self.cal4).grid(row=1,column=4)
			Label(self.tdecry,text = "The decrypted text will be shown in the initial text window.").grid(row=2,column=0)
			Button(self.tdecry,text="Start",command=self.text_de).grid(row=2,column=2)

	def cal4(self):
		self.d=int(self.keya.get())
		self.n=int(self.keyb.get())
		text=self.text.get('0.0',END)
		self.list1=[]
		for a in text:
			self.list1.append(ord(a))
		self.list1.pop()      
		
	def text_de(self):
		self.list2=[]
		for a in self.list1 :
			c = decryption(a,self.d,self.n)
			self.list2.append(c)
		#print self.list2
		self.list3=[]
		for b in self.list2:
			self.list3.append(unichr(b))
		self.text.delete(0.0,10.0)
		for m in self.list3:
			self.text.insert(END,m)
		tkMessageBox.showinfo("tishi","Decryption Finished!")
		self.tdecry.destroy()

	def DiS(self):
		self.ds=Tk()
		self.ds.title("Digital Signature")
		Label(self.ds,text="You can make your own Digital Signature Here!").grid(row=0,column=0)
		Label(self.ds,text="Input the strings(must in English):").grid(row=1,column=0)
		self.string=Entry(self.ds)
		self.string.grid(row=1,column=1)
		Button(self.ds,text="Start",command=self.md5).grid(row=1,column=2)

	def md5(self):
		m = hashlib.md5()
		a=self.string.get()
		m.update(a)
		n=m.hexdigest()
		tkMessageBox.showinfo("Congratulations!","You have your own Digital Signature now!\nYour Digitial Signature is %s"%n)
		self.ds.destory()

"""
			if self.method ==1 :
				#Label(encry,text="You choose simple method to encrypt").grid(row=1,column=1)
				tkMessageBox.askquestion("tishi","Do you want to encrypt?")
"""

"""
	def  showfile(self):
		tkMessageBox.showinfo("Message",self.filename.get())
"""
app=App()
app.title("Welcome to En&Decrypt")
app.mainloop()
