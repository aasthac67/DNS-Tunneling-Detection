from scapy.all import *
import sys
import math
from io import StringIO
import numpy as np
import time
import pickle
from collections import Counter
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC, NuSVC, LinearSVC


parts = []
common = dict()

def mode(sample):
    c = Counter(sample)
    return [k for k, v in c.items() if v == c.most_common(1)[0][1]]

def calculateEntropy(text):
    if not text: 
        return 0 
    entropy = 0
    trantab = {None: "._-"}
    text = str(text).translate(trantab)
    for x in range(256): 
        p_x = float(text.count(chr(x)))/len(text) 
        if p_x > 0: 
            entropy += - p_x*math.log(p_x, 2) 
    return entropy

def filterML(qr): 
    entropy = calculateEntropy(qr)
    test_data = np.array([entropy]).reshape(1,1)
    start = time.time()
    model1 = pickle.load(open("RandomForest.pkl", 'rb'))
    model2 = pickle.load(open("DecisionTree.pkl", 'rb'))
    model3 = pickle.load(open("SVC.pkl", 'rb'))
    pred1 = model1.predict(test_data)
    pred2 = model2.predict(test_data)
    pred3 = model3.predict(test_data)

    final_pred = np.array([])
    for i in range(0,len(test_data)):
        final_pred = np.append(final_pred, mode([pred1[i], pred2[i], pred3[i]]))

    if final_pred[0] == 0:
        print("Genuine Query "  + qr)
    elif final_pred[0] == 1:
        print("DNS Tunneling Query " + qr)
    end = time.time()
    print("The time taken is: ",(end-start)*1000,"millisec")

def filterFQDN(qr):
    global common
    global parts
    if qr not in common.keys():
        count=0
        l1=0
        l2=0
        for p in qr.split("."):
            if p not in parts:
                count+=1
                l1=l1+len(p)
            l2=l2+len(p)
        sim = count/len(qr.split("."))
        if l2 == 0:
            attack_data.append(0)
            print("OK " + qr)
            return False
        sim2=l1/l2
        if sim <= 0.75 and sim2 >= 0.8:
            print("DNS Tunneling Query " + qr)
        else:
            print("Genuine Query " + qr)
        for p in qr.split("."):
            parts.append(p)
        common[qr] = 1
    else:
        common[qr] += 1
        print("OK " + qr)

def filterQuery(x):
    txt = x.summary()
    txt = txt.split(' ')[8]
    qr = txt[3:-4]
    print("Query :" + qr)
    filterFQDN(qr)
    filterML(qr)

def testDNSTunneling():
    qrs = ["dnscat.61eb014a4ad0898579ce800018fb2ab880", "dnscat.1361014a4af9480966b594001e35223999", "dnscat.5fb9014a4acf5551cf7fea00280c26976a"]
    for qr in qrs:
        filterFQDN(qr)
        filterML(qr)

testDNSTunneling()
a=sniff(lfilter=lambda x: x.haslayer(DNS) and x.getlayer(DNS).qr == 0 and filterQuery(x), count=10)
