from pymongo import MongoClient
import sys, argparse, random
from numpy import array
from sklearn import model_selection, neural_network
from sklearn.preprocessing import StandardScaler
from progressbar import *
from sklearn.metrics import confusion_matrix
import logging, pickle
from statistics import mean
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

def NeuralNetwork(filename):
    client = MongoClient('mongodb://localhost:27017/')
    db_ = client['ClearData']
    collection_ = db_['TimeFrame5S']
    cursor = collection_.find({}, {'_id': False})

    toDrop = ['timeStampStart', 'timeStampEnd', 'timeWindow', 'classificationIn']

    data = []

    dataNormalActivity = []
    dataUnusualActivity = []

    for doc in cursor:
        tmp = [v for (k,v) in sorted(doc.items()) if k not in toDrop]
        tmp.append(doc['classificationIn'])
        dataNormalActivity.append(tmp)

    db_ = client['ClearDataAnomalies']
    collection_ = db_['TimeFrame5S']
    cursor = collection_.find({}, {'_id': False})

    for doc in cursor:
        tmp = [v for (k, v) in sorted(doc.items()) if k not in toDrop]
        tmp.append(doc['classificationIn'])
        dataUnusualActivity.append(tmp)

    data.extend(dataNormalActivity)
    data.extend(dataUnusualActivity)

    random.shuffle(data) # randomize data order
    label = [x[-1] for x in data]                       # extract output
    data =  [[float(y) for y in x[:-1]] for x in data]  # extract input

    normalizer = StandardScaler()

    normalizedData = normalizer.fit_transform(data)  # normalize features

    dataNumPy = array(normalizedData)
    labelNumPy = array(label)

    XTrain = dataNumPy[:int(len(dataNumPy) * 0.8)]
    yTrain = labelNumPy[:int(len(dataNumPy) * 0.8)]

    XTest = dataNumPy[int(len(dataNumPy) * 0.8):]
    yTest = labelNumPy[int(len(dataNumPy) * 0.8):]

    accuracyTestNN_ = []
    accuracyTrainNN_ = []
    finalAcc_NN_ = []
    trueNegatives, falsePositives, falseNegatives, truePositives = [], [], [], []

    iterations = 300
    bar = ProgressBar(widgets=['Progress: ', Percentage(), ' ', Bar(marker='#', left='[', right=']'),
                               ' ', ETA(), ' ', FileTransferSpeed()], maxval=iterations)
    bar.start()
    for i in range(0, iterations):
        bar.update(i)
        modelNN = neural_network.MLPClassifier(solver='lbfgs', activation='logistic', alpha=0.000001, hidden_layer_sizes=(30, 15, 1),
                                random_state=1)
        accuracyTestNN, accuracyTrainNN = accuracyFromTest(XTrain, yTrain, modelNN)  # train/cross-validation
        finalAcc_NN = (modelNN.score(XTest, yTest) * 100)  # final test

        yPred = modelNN.predict(XTest)
        matrix = confusion_matrix(yTest, yPred).ravel()
        trueNegatives.append(matrix[0])
        falsePositives.append(matrix[1])
        falseNegatives.append(matrix[2])
        truePositives.append(matrix[3])

        accuracyTestNN_.append(accuracyTestNN)
        accuracyTrainNN_.append(accuracyTrainNN)
        finalAcc_NN_.append(finalAcc_NN)
        pickle.dump(modelNN, open(filename, 'wb'))

    bar.finish()
    NN = mean(finalAcc_NN_)
    meanFalsePositives = mean(falsePositives)
    meanFalseNegatives = mean(falseNegatives)
    print('finalAcc_NN = ', NN)
    print('Test accuracy (min, max) = ', '(', min(accuracyTestNN_), ',', max(accuracyTestNN_), ')')
    print('Final accuracy (min, max)= ', '(', min(finalAcc_NN_), ',', max(finalAcc_NN_), ')')
    print('Mean False Positives = ', meanFalsePositives, ')')
    print('Mean False Negatives = ', meanFalseNegatives, ')')

def test_neuralNetwork_btm(filename):

    print('########################')
    print('# 1 - Normal data      #')
    print('# 2 - Anomaly data     #')
    print('# 3 - Both data        #')
    print('########################')
    method = input('Choose a method: ')
    if (int(method) not in [1,2,3]):
        print ('Invalid input')
        exit()

    client = MongoClient('mongodb://localhost:27017/')
    if int(method) == 2:
        db_ = client['ClearAnomalies']
    else:
        db_ = client['ClearUserProfiling']

    collection_ = db_['TimeFrame2M']
    cursor = collection_.find({}, {'_id': False})

    toDrop = ['timeStampStart', 'timeStampEnd', 'timeWindow', 'classificationIn', 'skewBytesIn', 'kurtosisBytesIn',
              'firstQBytesIn', 'thirdQBytesIn',
              'skewBytesOut', 'kurtosisBytesOut', 'firstQBytesOut', 'thirdQBytesOut', 'skewDeltaIn', 'kurtosisDeltaIn',
              'firstQDeltaIn', 'thirdQDeltaIn',
              'skewDeltaOut', 'kurtosisDeltaOut', 'firstQDeltaOut', 'thirdQDeltaOut', 'skewDistance',
              'kurtosisDistance', 'firstQDistance', 'thirdQDistance',
              'skewAngle', 'kurtosisAngle', 'firstQAngle', 'thirdQAngle', 'skewConnectionToSameIP',
              'kurtosisConnectionToSameIP',
              'firstQConnectionToSameIP', 'thirdQConnectionToSameIP']

    data = []

    dataNormalActivity = []
    dataUnusualActivity = []

    for doc in cursor:
        tmp = [v for (k, v) in sorted(doc.items()) if k not in toDrop]
        tmp.append(doc['classificationIn'])
        dataNormalActivity.append(tmp)

    if int(method) == 3:
        db_ = client['ClearAnomalies']
        collection_ = db_['TimeFrame2M']
        cursor = collection_.find({}, {'_id': False})

        for doc in cursor:
            tmp = [v for (k, v) in sorted(doc.items()) if k not in toDrop]
            tmp.append(doc['classificationIn'])
            dataUnusualActivity.append(tmp)

    data.extend(dataNormalActivity)

    if int(method) == 3:
        data.extend(dataUnusualActivity)

    random.shuffle(data)  # randomize data order
    label = [x[-1] for x in data]  # extract output
    data = [[float(y) for y in x[:-1]] for x in data]  # extract input

    normalizer = StandardScaler()

    normalizedData = normalizer.fit_transform(data)  # normalize features

    dataNumPy = array(normalizedData)
    labelNumPy = array(label)

    XTest = dataNumPy[int(len(dataNumPy) * 0.6):]
    yTest = labelNumPy[int(len(dataNumPy) * 0.6):]

    finalAcc_NN_ = []

    trueNegatives, falsePositives, falseNegatives, truePositives = [], [], [], []

    with (open(filename, 'rb')) as file:
        while True:
            try:
                modelNN = pickle.load(file)
            except EOFError:
                break

            finalAcc_NN = (modelNN.score(XTest, yTest) * 100)  # final test

            yPred = modelNN.predict(XTest)
            matrix = confusion_matrix(yTest, yPred).ravel()
            trueNegatives.append(matrix[0])
            falsePositives.append(matrix[1])
            falseNegatives.append(matrix[2])
            truePositives.append(matrix[3])

            finalAcc_NN_.append(finalAcc_NN)
    file.close()

    NN = mean(finalAcc_NN_)
    meanFalsePositives = mean(falsePositives)
    meanFalseNegatives = mean(falseNegatives)
    print('Final Accuracy = ', NN)
    print('Mean False Positives = ', meanFalsePositives, ')')
    print('Mean False Negatives = ', meanFalseNegatives, ')')

def test_neuralNetwork_stm(filename):
    print('########################')
    print('# 1 - Normal data      #')
    print('# 2 - Anomaly data     #')
    print('# 3 - Both data        #')
    print('########################')
    method = input('Choose a method: ')
    if (int(method) not in [1, 2, 3]):
        print('Invalid input')
        exit()

    client = MongoClient('mongodb://localhost:27017/')
    if int(method) == 2:
        db_ = client['ClearAnomalies']
    else:
        db_ = client['ClearUserProfiling']

    collection_ = db_['TimeFrame5S']
    cursor = collection_.find({}, {'_id': False})

    toDrop = ['timeStampStart', 'timeStampEnd', 'timeWindow', 'classificationIn']

    data = []

    dataNormalActivity = []
    dataUnusualActivity = []

    for doc in cursor:
        tmp = [v for (k, v) in sorted(doc.items()) if k not in toDrop]
        tmp.append(doc['classificationIn'])
        dataNormalActivity.append(tmp)

    if int(method) == 3:
        db_ = client['ClearAnomalies']
        collection_ = db_['TimeFrame5S']
        cursor = collection_.find({}, {'_id': False})

        for doc in cursor:
            tmp = [v for (k, v) in sorted(doc.items()) if k not in toDrop]
            tmp.append(doc['classificationIn'])
            dataUnusualActivity.append(tmp)

    data.extend(dataNormalActivity)

    if int(method) == 3:
        data.extend(dataUnusualActivity)

    random.shuffle(data)  # randomize data order
    label = [x[-1] for x in data]  # extract output
    data = [[float(y) for y in x[:-1]] for x in data]  # extract input

    normalizer = StandardScaler()

    normalizedData = normalizer.fit_transform(data)  # normalize features

    dataNumPy = array(normalizedData)
    labelNumPy = array(label)

    XTest = dataNumPy[int(len(dataNumPy) * 0.6):]
    yTest = labelNumPy[int(len(dataNumPy) * 0.6):]

    finalAcc_NN_ = []

    trueNegatives, falsePositives, falseNegatives, truePositives = [], [], [], []

    with (open(filename, 'rb')) as file:
        while True:
            try:
                modelNN = pickle.load(file)
            except EOFError:
                break

            finalAcc_NN = (modelNN.score(XTest, yTest) * 100)  # final test

            yPred = modelNN.predict(XTest)
            matrix = confusion_matrix(yTest, yPred).ravel()
            trueNegatives.append(matrix[0])
            falsePositives.append(matrix[1])
            falseNegatives.append(matrix[2])
            truePositives.append(matrix[3])

            finalAcc_NN_.append(finalAcc_NN)
    file.close()

    NN = mean(finalAcc_NN_)
    meanFalsePositives = mean(falsePositives)
    meanFalseNegatives = mean(falseNegatives)
    print('Final accuracy = ', NN)
    print('Mean False Positives = ', meanFalsePositives)
    print('Mean False Negatives = ', meanFalseNegatives)

def read_file(filename):
    client = MongoClient('mongodb://localhost:27017/')
    databases = client.database_names()
    databases = sorted([x for x in databases if 'Single' in x])
    for i in range(len(databases)):
        print('# {} {:<4} '.format(i, databases[i]))
    id = input('Choose Database : ')
    database = databases[int(id)]
    # db = client['UserProfiling']
    collections = client[database].collection_names()
    collections = sorted([x for x in collections if '_' in x])
    for i in range(len(collections)):
        print('# {} {:<4} '.format(i, collections[i]))
    id = input('Choose Collection : ')

    db_ = client[database]

    collection = collections[int(id)]
    collection_ = db_[collection]
    cursor = collection_.find({}, {'_id': False})

    toDrop = ['timeStampStart', 'timeStampEnd', 'timeWindow', 'classificationIn', 'skewBytesIn', 'kurtosisBytesIn',
              'firstQBytesIn', 'thirdQBytesIn',
              'skewBytesOut', 'kurtosisBytesOut', 'firstQBytesOut', 'thirdQBytesOut', 'skewDeltaIn', 'kurtosisDeltaIn',
              'firstQDeltaIn', 'thirdQDeltaIn',
              'skewDeltaOut', 'kurtosisDeltaOut', 'firstQDeltaOut', 'thirdQDeltaOut', 'skewDistance',
              'kurtosisDistance', 'firstQDistance', 'thirdQDistance',
              'skewAngle', 'kurtosisAngle', 'firstQAngle', 'thirdQAngle', 'skewConnectionToSameIP',
              'kurtosisConnectionToSameIP',
              'firstQConnectionToSameIP', 'thirdQConnectionToSameIP']

    data = []

    dataNormalActivity = []

    for doc in cursor:
        tmp = [v for (k, v) in sorted(doc.items()) if k not in toDrop]
        tmp.append(doc['classificationIn'])
        dataNormalActivity.append(tmp)

    data.extend(dataNormalActivity)

    random.shuffle(data)  # randomize data order
    label = [str(x[-1]) for x in data]  # extract output
    data = [[float(y) for y in x[:-1]] for x in data]  # extract input

    normalizer = StandardScaler()

    print (len(data[0]))

    normalizedData = normalizer.fit_transform(data)  # normalize features

    dataNumPy = array(normalizedData)
    labelNumPy = array(label)

    XTest = dataNumPy
    yTest = labelNumPy

    finalAcc_NN_ = []
    trueNegatives, falsePositives, falseNegatives, truePositives = [], [], [], []

    with (open(filename, 'rb')) as file:
        while True:
            try:
                modelNN = pickle.load(file)
            except EOFError:
                break

            finalAcc_NN = (modelNN.score(XTest, yTest) * 100)  # final test

            yPred = modelNN.predict(XTest)
            matrix = confusion_matrix(yTest, yPred).ravel()
            trueNegatives.append(matrix[0])
            falsePositives.append(matrix[1])
            falseNegatives.append(matrix[2])
            truePositives.append(matrix[3])

            finalAcc_NN_.append(finalAcc_NN)
    file.close()

    NN = mean(finalAcc_NN_)
    meanFalsePositives = mean(falsePositives)
    meanFalseNegatives = mean(falseNegatives)
    print('finalAcc_NN = ', NN)
    print('Mean False Positives = ', meanFalsePositives, ')')
    print('Mean False Negatives = ', meanFalseNegatives, ')')

def goTrain_Test(model, X_train, X_test, y_train, y_test):  #training function
    model.fit(X_train, y_train)
    return model.score(X_train, y_train) * 100, model.score(X_test, y_test) * 100

def accuracyFromTest(XTrain, yTrain, model):
    kf = model_selection.KFold(n_splits=10,shuffle=True)        #k-fold
    accuracyTrain = []
    accuracyTest = []

    for train_index, test_index in kf.split(XTrain):
        X_train, X_test = XTrain[train_index], XTrain[test_index]
        y_train, y_test = yTrain[train_index], yTrain[test_index]
        accuracy_train, accuracy_test = goTrain_Test(model, X_train, X_test, y_train, y_test)
        accuracyTrain.append(accuracy_train)
        accuracyTest.append(accuracy_test)
    accuracyTrain = sum(accuracyTrain) / len(accuracyTrain)
    accuracyTest = sum(accuracyTest) / len(accuracyTest)

    return accuracyTest, accuracyTrain

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='MachineLearning is a script to train, save and load the agent using NeuralNetworks. After the load,'
                    ' it tests and presents the result')
    parser.add_argument('-d', action="store_true", dest='dump',
                        help='Dump Ml objects to file')
    parser.add_argument('-l', action="store_true", dest='load',
                        help='Load Ml objects')
    parser.add_argument('-f', action="store", dest='file',
                        help='File to save or load the serialized object')
    parser.add_argument('-tb', action="store_true", dest='test_big',
                        help='Test NeuralNetwork with features mapped by big time window.')
    parser.add_argument('-ts', action="store_true", dest='test_small',
                        help='Test NeuralNetwork with features mapped by small time window.')

    args = parser.parse_args()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    args = vars(args)

    if args['file']:
        if args['dump']:
            NeuralNetwork(args['file'])
        elif args['load']:
            read_file(args['file'])
        elif args['test_big']:
            test_neuralNetwork_btm(args['file'])
        elif args['test_small']:
            test_neuralNetwork_stm(args['file'])
        else:
            parser.print_help()
    else:
        parser.print_help()
