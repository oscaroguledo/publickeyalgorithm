import random
import math

class PublicKeyAlgorithm():
    def __init__(self,key_length) -> None:
        self.key_length = key_length
        self.ascii_symbols = {
            '�': '00000000', '': '00000001', '': '00000010', '': '00000011',
            '': '00000100', '': '00000101', '': '00000110', 'BEL': '00000111',
            '': '00001000', '\t': '00001001', '\n': '00001010', '': '00001011',
            '\f': '00001100', 'CR': '00001101', '': '00001110', '': '00001111',
            '': '00010000', '': '00010001', '': '00010010', '': '00010011',
            '': '00010100', '': '00010101', '': '00010110', '': '00010111',
            '': '00011000', '': '00011001', '': '00011010', '': '00011011',
            '': '00011100', '': '00011101', '': '00011110', '': '00011111',
            ' ': '00100000', '!': '00100001', '"': '00100010', '#': '00100011',
            '$': '00100100', '%': '00100101', '&': '00100110', "'": '00100111',
            '(': '00101000', ')': '00101001', '*': '00101010', '+': '00101011',
            ',': '00101100', '-': '00101101', '.': '00101110', '/': '00101111',
            '0': '00110000', '1': '00110001', '2': '00110010', '3': '00110011',
            '4': '00110100', '5': '00110101', '6': '00110110', '7': '00110111',
            '8': '00111000', '9': '00111001', ':': '00111010', ';': '00111011',
            '<': '00111100', '=': '00111101', '>': '00111110', '?': '00111111',
            '@': '01000000', 'A': '01000001', 'B': '01000010', 'C': '01000011',
            'D': '01000100', 'E': '01000101', 'F': '01000110', 'G': '01000111',
            'H': '01001000', 'I': '01001001', 'J': '01001010', 'K': '01001011',
            'L': '01001100', 'M': '01001101', 'N': '01001110', 'O': '01001111',
            'P': '01010000', 'Q': '01010001', 'R': '01010010', 'S': '01010011',
            'T': '01010100', 'U': '01010101', 'V': '01010110', 'W': '01010111',
            'X': '01011000', 'Y': '01011001', 'Z': '01011010', '[': '01011011',
            '\\': '01011100', ']': '01011101', '^': '01011110', '_': '01011111',
            '`': '01100000', 'a': '01100001', 'b': '01100010', 'c': '01100011',
            'd': '01100100', 'e': '01100101', 'f': '01100110', 'g': '01100111',
            'h': '01101000', 'i': '01101001', 'j': '01101010', 'k': '01101011',
            'l': '01101100', 'm': '01101101', 'n': '01101110', 'o': '01101111',
            'p': '01110000', 'q': '01110001', 'r': '01110010', 's': '01110011',
            't': '01110100', 'u': '01110101', 'v': '01110110', 'w': '01110111',
            'x': '01111000', 'y': '01111001', 'z': '01111010', '{': '01111011',
            '|': '01111100', '}': '01111101', '~': '01111110', '\x7F': '01111111',
        }
        pass

    def __alpha_to_binary(self,message):
        binary_message =""
        for char in message:
            if char in self.ascii_symbols.keys():
                ch = self.ascii_symbols[char][1:]
                binary_message+=ch
            else:
                binary_message+=bin(ord(char))[2:]

        return binary_message

    def __binary_to_aplha(self,binary_message):
        b =""
        for message in binary_message:
            b+=message
        # Adjust slicing to ensure the last chunk may have fewer than 7 bits since since ascii is 8 bits-- 
        b=[b[i:i+7] for i in range(0,len(b),7)]
        alpha_message =""
        for string in b:
            alpha_message+=chr(int(string, 2))
        return alpha_message

    def __get_e(self,n):
        int_list=[]
        for i in range(0,n):
            l = sum(int_list) if len(int_list) > 0 else len(int_list)
            a=l+1
            b=2*a
            x= random.randint(a,b)
            int_list.append(x)
        return int_list

    def __is_prime(self,n): 
        if n<=1:
            return True
        if n <= 3:
            return False
        if n % 2 ==0 or n %3 ==0:
            return False
        
        a=5
        while a*a <=n:
            if n % a == 0 or n % (a+2) == 0:
                return False
            a+=6
        return True

    def __get_q(self,array):
        b = array[len(array)-1]
        while True:
            q= random.randint(1,b*b)

            if q % 2 ==0:# if q is an even number add 1
                q+=1
            if self.__is_prime(q):
                if q > 2*b:
                    return q

    def __get_w(self,q):
        w=2
        while True:
            if math.gcd(w,q)==1:
                return w
            w+=1
        
    def gen_random_key(self):
        e = self.__get_e(self.key_length)
        q = self.__get_q(e)
        w = self.__get_w(q)

        h = [(w*i)%q for i in e]
        private_key = (e,q,w)
        public_key = (h)
        res = {"private_key":private_key, "public_key":public_key}
        return res
    
    def encrypt(self,message, key):
        print("\033[93mEncrypting using the public key ...\033[0m")

        #converting characters to binary-----------
        h = key
        n = len(h)
        bin_m =self.__alpha_to_binary(message)
        plaintext = [(bin_m[i:i+n]) for i in range(0,len(bin_m)-1,n)]
        print(f"\033[92m{n}-bit plaintext : {plaintext} \033[0m\n")

        #"dividing the message into blocks"
        
        cipher =[]
        pad =0
        for block in plaintext:
            l = len(block)
            if l//len(h) ==0:
                pad=len(h)-l
                block=block +("0"*pad) 
            m = [b for b in block]
            cipher_block = 0
            
            for i, j in zip(m,h):
                try:
                    cipher_block += int(i) * int(j)
                except IndexError:
                    cipher_block +=0

            #print("blocked message:",m)
            cipher.append(cipher_block)
        return cipher,pad
            
    def decrypt(self,cipher, key, pad):
        # using the private key as a param---
        print("\033[93mDecrypting using the private key ...\033[0m")
        e = key[0]
        w = key[2]
        w_inv = pow(w,-1)
        q = key[1]
        plaintext=[]
        for block in cipher:
            c_prime=float(block)*(w_inv % q)
            m=""
            for i in reversed(e):
                if c_prime >= i:
                    m = m[:0]+"1"+m[0:]
                    c_prime -=i
                else:
                    m = m[:0]+"0"+m[0:]  
            plaintext.append(m)
        if pad > 0 :
            plaintext[-1]=plaintext[-1][:-pad]

        print(f"{len(e)}-bit decrypted message: \033[92m{plaintext} \033[0m\n")

        alpha_m =self.__binary_to_aplha(plaintext)
        
        return alpha_m

def main():
    n = int(input(f"Select you key length :\n"))

    #selecting commandline or text file for the plaintext----------------------------------
    ans = input("Enter message via command line or text file: C/T \n")
    
    while ans not in ["c","C","T","t"]:
        ans =input("please select C or T (commandline or text file)\n")
        if ans in ["c","C","T","t"]:
            break
    if ans =="C" or ans =="c":
        message = input(f"Enter your message : \n")+" "
    if ans == "T" or ans =="t":
        while True:
            plaintext = input("Enter the name of your file e.g plaintext.txt \n")
            try:
                with open(plaintext, 'r') as file:
                    message = file.read()
                break
            except FileNotFoundError as error:
                print("\033[91m"+str(error)+"\033[0m")
                plaintext = input("Enter the name of your file e.g plaintext.txt \n")
    #------------------------------------------------------------------------------------

    ##implementing the algorithm---------------------------------------------------------------
    algo = PublicKeyAlgorithm(key_length=n)

    key = algo.gen_random_key()
    print("key:","\033[92m"+str(key)+"\033[0m")
    print("\n")

    ecrypted_message, pad = algo.encrypt(message=message, key=key['public_key'])
    print(f"{n}-bit ciphertext:\033[92m {ecrypted_message}\033[0m \n")
    print(f"padding: \033[92m{pad}\033[0m \n")

    decrypted_message = algo.decrypt(cipher = ecrypted_message,key=key['private_key'], pad=pad)
    print(f"decrypted text:\033[92m {decrypted_message} \033[0m\n")
    #-----------------------------------------------------------------------------------------

if __name__ == "__main__":
    main()
