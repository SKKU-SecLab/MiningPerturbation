def run_process(a,b,x, changed_mal):
    
    df_malicious = a.copy()
    df_benign    = b.copy()
    
    df_mal_web_mine = changed_mal.copy()

    from tsfresh import extract_features, select_features
    from tsfresh.utilities.dataframe_functions import impute
    from tsfresh import extract_features
    from tsfresh.feature_selection.relevance import calculate_relevance_table

    df_malicious.reset_index(drop=True, inplace=True) #reset index
    df_malicious['id']= np.floor(df_malicious.index.array/10)
    df_benign.reset_index(drop=True, inplace=True) #reset index
    df_benign['id']= np.floor(df_benign.index.array/10)

    df_mal_web_mine.reset_index(drop=True, inplace=True) #reset index
    df_mal_web_mine['id']= np.floor(df_mal_web_mine.index.array/10)
    
    tf1=tsfresh.extract_features(df_malicious,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf1['class']= 1

    tf2=tsfresh.extract_features(df_benign,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf2['class']= 0

    tf3=tsfresh.extract_features(df_mal_web_mine,impute_function=impute, column_kind='Is_malicious',
                                 column_id='id',column_sort="Time",column_value = "Length")
    tf3['class']= 1

    tf2.columns = tf1.columns
    tf3.columns = tf1.columns

    features=pd.concat([tf1,tf2])
    features_changed_mal = pd.concat([tf3,tf2])

    features2 = features.copy()
    features_changed_mal2 = features_changed_mal.copy()

    features2.reset_index(drop=True, inplace=True)
    features_changed_mal2.reset_index(drop=True, inplace=True)

    y = pd.Series(data = features2['class'], index=features2.index)
    y_changed_mal = pd.Series(data = features_changed_mal2['class'], index=features_changed_mal2.index)

    from tsfresh.examples import load_robot_execution_failures
    from tsfresh import extract_features, select_features
    from tsfresh.feature_selection.relevance import calculate_relevance_table

    relevance_table = calculate_relevance_table(features2, y)
    relevance_table = relevance_table[relevance_table.relevant]
    relevance_table.sort_values("p_value", inplace=True)
    print("relevance_table " , relevance_table.shape)
    relevance_table_changed_mal = calculate_relevance_table(features_changed_mal2, y_changed_mal)
    relevance_table_changed_mal = relevance_table_changed_mal[relevance_table_changed_mal.relevant]
    relevance_table_changed_mal.sort_values("p_value", inplace=True)
    print("relevance_table_changed_mal " , relevance_table_changed_mal.shape)

    best_features = pd.DataFrame(relevance_table[relevance_table['p_value'] <= 0.05])
 
    mal_pktPlus_features = pd.DataFrame(relevance_table_changed_mal)

    if (len(mal_pktPlus_features) >= len(best_features)):
      mal_pktPlus_features = mal_pktPlus_features[:len(best_features)]
    else:
      best_features = best_features[:len(mal_pktPlus_features)]
      
    df_ML = pd.DataFrame()
    df_ML_mal = pd.DataFrame()

    for pkt in best_features:
        df_ML[best_features.feature] = features[best_features.feature]
      
    for pkt in mal_pktPlus_features:
        df_ML_mal[mal_pktPlus_features.feature] = features_changed_mal2[mal_pktPlus_features.feature]
    
    # df_ML.columns = df_ML_mal.columns    

    final = ML_Process(df_ML,x, df_ML_mal)

    return final

def ML_Process(df_ML,x, df_ML_mal):
    df_results = x.copy() 
    print('let the ml starts')
  
    from sklearn import neighbors, metrics
    from sklearn.preprocessing import LabelEncoder

    
    X = df_ML.drop('class',axis=1).to_numpy()
    X_mal = df_ML_mal.drop('class',axis=1).to_numpy()
    
    y = df_ML['class'].to_numpy()
    y_mal = df_ML_mal['class'].to_numpy()

    
    # from sklearn.model_selection import train_test_split
    Le = LabelEncoder()
    for i in range(len(X[0])):
        X[:, i] = Le.fit_transform(X[:, i])
    for i in range(len(X_mal[0])):
        X_mal[:, i] = Le.fit_transform(X_mal[:, i])
    
    X_train = X
    y_train = y
    X_test = X_mal
    y_test = y_mal

    from sklearn.svm import SVC
    from sklearn import model_selection
    from sklearn.utils import class_weight
    from sklearn.metrics import classification_report
    from sklearn.metrics import confusion_matrix
    import numpy as np
    import pandas as pd
    y_train = y_train.ravel()
    dfs = []
    models = [
        ('SVM', SVC()), 
            ]
    results = []
    names = []
    scoring = ['accuracy', 'precision_weighted', 'recall_weighted', 'f1_weighted', 'roc_auc']
    target_names = ['malignant', 'benign']
    for name, model in models:
        kfold = model_selection.KFold(n_splits=5, shuffle=True, random_state=None)
        cv_results = model_selection.cross_validate(model, X_train, y_train, cv=kfold, 
                                                    scoring=scoring)
        clf = model.fit(X_train, y_train)
        y_pred = clf.predict(X_test)
        print(name)
        print(classification_report(y_test, y_pred, target_names=target_names))
        results.append(cv_results)
        names.append(name)
        this_df = pd.DataFrame(cv_results)
        this_df['model'] = name
        dfs.append(this_df)
        df_resulta = df_results.append(dfs)
        final = pd.concat(dfs, ignore_index=True)
        print(final)

    return(final)