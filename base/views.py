from django.shortcuts import render
from rest_framework.decorators import api_view
from rest_framework.response import Response
import pandas as pd
import itertools
from sklearn.metrics import mean_squared_error, confusion_matrix, precision_score, recall_score, auc, roc_curve
from sklearn.model_selection import train_test_split
import pandas as pdA
import numpy as np
import random
import math
from collections import Counter
from sklearn import metrics
import matplotlib.pyplot as plt
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import xgboost as xgb
from lightgbm import LGBMClassifier
from xgboost import XGBClassifier
import os
import socket
import whois
from datetime import datetime
import time
from bs4 import BeautifulSoup
import urllib
import bs4
import os


suspicious = 0


def model_predictions_all(sample_list):
    global suspicious
    suspicious = 0
    import pandas as pd

    def process_input_dict(input_dict):
        # Create dataframe from input dictionary
        df = pd.DataFrame.from_dict([input_dict])

        # Create dataframe with remaining columns
        df_c = df.drop('URL', axis=1)

        # Return dataframe
        return df[['URL']], df_c

    def process_input_list(input_list):
        # Create dataframe from input list
        df = pd.DataFrame([input_list], columns=['Request', 'AcceptHdr',
                          'Encoding', 'Lang', 'Agent', 'Cookie', 'Cdata', 'Clength', 'URL'])

        # Create dataframe with remaining columns
        df_c = df.drop('URL', axis=1)

        # Return dataframes
        return df[['URL']], df_c

    df, df_c = process_input_dict(sample_list)

    # Length of URL
    df_c['Accept_Header_Length'] = df_c['AcceptHdr'].apply(
        lambda i: len(str(i)))

    # count number of sub-directories
    from urllib.parse import urlparse

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')
    df_c['Accept_Header_SubDirectory'] = df_c['AcceptHdr'].apply(
        lambda i: no_of_dir(i))

    # Length of URL
    df_c['Cookie_Length'] = df_c['Cookie'].apply(lambda i: len(str(i)))

    df_c['cookie_less_than_count'] = df_c['Cookie'].apply(
        lambda i: i.count('<'))
    df_c['cookie_open_brace_count'] = df_c['Cookie'].apply(
        lambda i: i.count('{'))
    df_c['cookie_close_brace_count'] = df_c['Cookie'].apply(
        lambda i: i.count('}'))
    df_c['cookie_plus_count'] = df_c['Cookie'].apply(lambda i: i.count('+'))
    df_c['cookie_minus_count'] = df_c['Cookie'].apply(lambda i: i.count('-'))
    df_c['cookie_double_quote_count'] = df_c['Cookie'].apply(
        lambda i: i.count('"'))
    df_c['cookie_colon_count'] = df_c['Cookie'].apply(lambda i: i.count(':'))
    df_c['cookie_semicolon_count'] = df_c['Cookie'].apply(
        lambda i: i.count(';'))
    df_c['cookie_asterisk_count'] = df_c['Cookie'].apply(
        lambda i: i.count('*'))
    df_c['cookie_backtick_count'] = df_c['Cookie'].apply(
        lambda i: i.count('`'))
    df_c['cookie_tilde_count'] = df_c['Cookie'].apply(lambda i: i.count('~'))
    df_c['cookie_ampersand_count'] = df_c['Cookie'].apply(
        lambda i: i.count('&'))
    df_c['cookie_exclamation_count'] = df_c['Cookie'].apply(
        lambda i: i.count('!'))

    # count cookie special characters

    def ss_count(string):
        # Declaring variable for special characters
        special_char = 0

        for i in range(0, len(string)):
            # len(string) function to count the
            # number of characters in given string.

            ch = string[i]

            # .isalpha() function checks whether character
            # is alphabet or not.
            if (string[i].isalpha()):
                continue
              # .isdigit() function checks whether character
              # is a number or not.
            elif (string[i].isdigit()):
                continue
            else:
                special_char += 1
        return special_char

    df_c['special_characters'] = df_c['Cookie'].apply(lambda i: ss_count(i))

    del df_c['AcceptHdr']

    from sklearn.preprocessing import LabelEncoder

    lb_make = LabelEncoder()
    df_c["Request_code"] = lb_make.fit_transform(df_c["Request"])
    df_c["Request_code"].value_counts()
    del df_c['Request']

    df_c["Encoding_code"] = lb_make.fit_transform(df_c["Encoding"])
    df_c["Encoding_code"].value_counts()
    del df_c['Encoding']

    df_c["Lang_code"] = lb_make.fit_transform(df_c["Lang"])
    df_c["Lang_code"].value_counts()
    del df_c['Lang']

    df_c["Agent_code"] = lb_make.fit_transform(df_c["Agent"])
    df_c["Agent_code"].value_counts()
    del df_c['Agent']

    del df_c['Cookie']

    df_c["Cdata_code"] = lb_make.fit_transform(df_c["Cdata"])
    df_c["Cdata_code"].value_counts()
    del df_c['Cdata']

    df_c['Clength'] = df_c['Clength'].astype('int64')

    import xgboost as xgb

    # Load the model
    xgb_model = xgb.Booster()
    xgb_model.load_model(
        r'models\xgboost_model_cookie.model')

    # Load the data
    X_cookie = df_c[['Clength', 'Accept_Header_Length', 'Accept_Header_SubDirectory', 'Cookie_Length', 'cookie_less_than_count', 'cookie_open_brace_count', 'cookie_close_brace_count', 'cookie_plus_count', 'cookie_minus_count', 'cookie_double_quote_count',
                     'cookie_colon_count', 'cookie_semicolon_count', 'cookie_asterisk_count', 'cookie_backtick_count', 'cookie_tilde_count', 'cookie_ampersand_count', 'cookie_exclamation_count', 'special_characters', 'Request_code', 'Encoding_code', 'Lang_code', 'Agent_code', 'Cdata_code']]
    dtest = xgb.DMatrix(X_cookie)

    # Get predictions
    y_pred_xgb_cookie = xgb_model.predict(dtest)
    # print("XGBoost predictions: ", y_pred_xgb_cookie)

    from keras.models import load_model

    # load the saved LSTM model
    lstm_model = load_model(
        r'models\lstm_model.h5')

    # load the saved CNN model
    cnn_model = load_model(
        r'models\CNN_model.h5')

    import os
    import warnings
    import numpy as np

    warnings.filterwarnings("ignore")
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

    # print("CNN.................................")

    X_cookie = df_c[['Clength', 'Accept_Header_Length', 'Accept_Header_SubDirectory', 'Cookie_Length', 'cookie_less_than_count', 'cookie_open_brace_count', 'cookie_close_brace_count', 'cookie_plus_count', 'cookie_minus_count', 'cookie_double_quote_count',
                     'cookie_colon_count', 'cookie_semicolon_count', 'cookie_asterisk_count', 'cookie_backtick_count', 'cookie_tilde_count', 'cookie_ampersand_count', 'cookie_exclamation_count', 'special_characters', 'Request_code', 'Encoding_code', 'Lang_code', 'Agent_code', 'Cdata_code']]
    X_cookie = np.reshape(X_cookie.values, (1, 23, 1))
    # print("X_cookie shape for CNN: ", X_cookie.shape)

    # CNN PREDICTION

    y_pred_cnn_cookie = cnn_model.predict(X_cookie)
    y_pred_cnn_cookie = np.round(y_pred_cnn_cookie)
    # print(int(y_pred_cnn_cookie))

    # LSTM PREDICION

    X_cookie = np.reshape(X_cookie, (X_cookie.shape[0], 1, X_cookie.shape[1]))
    # print("X_cookie shape for LSTM: ", X_cookie.shape)
    y_pred_lstm_cookie = lstm_model.predict(X_cookie)
    y_pred_lstm_cookie = np.round(y_pred_cnn_cookie)
    # print(int(y_pred_lstm_cookie))

    # URL prediction

    suspicious = 0

    import pandas as pd

    # assuming your dataframe is called df and the URL column is called url
    try:
        df['URL'] = df['URL'].apply(
            lambda x: 'http://www.example.com/' + x.split('/', 3)[3])
    except:
        suspicious += 1
        # print("wrog 1")

    import re
    # Use of IP or not in domain

    def having_ip_address(url):
        match = re.search(
            '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
            '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
            # IPv4 in hexadecimal
            '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'
            '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # Ipv6
        if match:
            # print match.group()
            return 1
        else:
            # print 'No matching pattern found'
            return 0

    try:
        df['use_of_ip'] = df['URL'].apply(lambda i: having_ip_address(i))
        del df['use_of_ip']
    except:
        # print("Malicious")
        suspicious += 1

        import re
    from urllib.parse import urlparse

    def abnormal_url(url):
        global suspicious
        try:
            hostname = urlparse(url).hostname
            hostname = str(hostname)
            match = re.search(hostname, url)
            if match:
                return 1
            else:
                return 0
        except Exception as e:
            # print("Malicious: ", e)
            suspicious += 1
            return -1  # return -1 to indicate an error occurred

    # assuming df is defined somewhere earlier in your code
    df['abnormal_url'] = df['URL'].apply(lambda i: abnormal_url(i))
    del df['abnormal_url']

    df['period_count'] = df['URL'].apply(lambda i: i.count('.'))
    df['www_count'] = df['URL'].apply(lambda i: i.count('www'))
    df['at_count'] = df['URL'].apply(lambda i: i.count('@'))
    from urllib.parse import urlparse

    def no_of_dir(url):
        urldir = urlparse(url).path
        return urldir.count('/')
    df['directory_count'] = df['URL'].apply(lambda i: no_of_dir(i))

    def no_of_embed(url):
        urldir = urlparse(url).path
        return urldir.count('//')
    df['embedded_domain_count'] = df['URL'].apply(lambda i: no_of_embed(i))

    def shortening_service(url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                          'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                          'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                          'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                          'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                          'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                          'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                          'tr\.im|link\.zip\.net',
                          url)
        if match:
            return 1
        else:
            return 0
    df['is_short_url'] = df['URL'].apply(lambda i: shortening_service(i))

    df['less_than_count'] = df['URL'].apply(lambda i: i.count('<'))
    df['open_brace_count'] = df['URL'].apply(lambda i: i.count('{'))
    df['close_brace_count'] = df['URL'].apply(lambda i: i.count('}'))
    df['plus_count'] = df['URL'].apply(lambda i: i.count('+'))
    df['minus_count'] = df['URL'].apply(lambda i: i.count('-'))
    df['double_quote_count'] = df['URL'].apply(lambda i: i.count('"'))
    df['colon_count'] = df['URL'].apply(lambda i: i.count(':'))
    df['semicolon_count'] = df['URL'].apply(lambda i: i.count(';'))
    df['asterisk_count'] = df['URL'].apply(lambda i: i.count('*'))
    df['backtick_count'] = df['URL'].apply(lambda i: i.count('`'))
    df['tilde_count'] = df['URL'].apply(lambda i: i.count('~'))
    df['ampersand_count'] = df['URL'].apply(lambda i: i.count('&'))
    df['exclamation_count'] = df['URL'].apply(lambda i: i.count('!'))

    def digit_count(url):
        digits = 0
        for i in url:
            if i.isnumeric():
                digits = digits + 1
        return digits
    df['digit_count'] = df['URL'].apply(lambda i: digit_count(i))

    def ss_count(string):
        # Declaring variable for special characters
        special_char = 0

        for i in range(0, len(string)):
            # len(string) function to count the
            # number of characters in given string.

            ch = string[i]

            # .isalpha() function checks whether character
            # is alphabet or not.
            if (string[i].isalpha()):
                continue
            # .isdigit() function checks whether character
            # is a number or not.
            elif (string[i].isdigit()):
                continue
            else:
                special_char += 1
        return special_char

    df['special_char_count'] = df['URL'].apply(lambda i: ss_count(i))

    df['percent_count'] = df['URL'].apply(lambda i: i.count('%'))
    df['question_mark_count'] = df['URL'].apply(lambda i: i.count('?'))
    # df['count-'] = df['url'].apply(lambda i: i.count('-'))
    df['equal_sign_count'] = df['URL'].apply(lambda i: i.count('='))
    # Length of URL
    df['url_length'] = df['URL'].apply(lambda i: len(str(i)))
    # Hostname Length
    df['hostname_length'] = df['URL'].apply(lambda i: len(urlparse(i).netloc))

    def iocs(url):
        global suspicious
        xss_and_sql_keywords = (
            # XSS attack keywords
            "<script>", "alert(", "onmouseover", "onload", "onclick", "onerror",
            "eval(", "document.cookie", "window.location", "innerHTML", "fromCharCode(",
            "encodeURIComponent(", "setTimeout(", "setInterval(", "xhr.open(", "xhr.send(",
            "parent.frames[", "prompt(", "confirm(", "formData.append(", "<img src=",
            "<audio src=", "<video src=", "<svg/onload=", "<marquee>", "<input type=\"text\" value=",
            "<a href=", "<link href=", "<iframe src=", "<body onload=", "<meta http-equiv=",
            "<form action=", "<textarea>", "<object data=", "<embed src=", "<style>", "<xss>", "<noscript>",
            "<applet>", "<base href=", "<s&#99;ript>", "al&#x65;rt(", "onmo&#x75;seover", "o&#x6e;load",
            "onclic&#x6b;", "onerror", "e&#x76;al(", "do&#x63;ument.cookie", "window.locat&#x69;on",
            "in&#x6e;erHTML", "fromCh&#x61;rCode(", "encodeURICompone&#x6e;t(", "setTim&#x65;out(",
            "setInt&#x65;rval(", "xhr.op&#x65;n(", "xhr.se&#x6e;d(", "parent.fr&#x61;mes[", "prom&#x70;t(",
            "confirm(", "formD&#x61;ta.append("
            # SQL injection keywords
            "OR", "AND", "--", ";", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE",
            "EXECUTE", "UNION", "JOIN", "DROP", "CREATE", "ALTER", "TRUNCATE", "TABLE", "DATABASE",
            "HAVING", "LIKE", "ESCAPE", "ORDER BY", "GROUP BY", "LIMIT", "OFFSET", "XOR", "NOT",
            "BETWEEN", "IN", "EXISTS",
            # Encrypted keywords
            "<s&#99;ript>", "al&#x65;rt(", "onmo&#x75;seover", "o&#x6e;load", "onclic&#x6b;", "onerror",
            "e&#x76;al(", "do&#x63;ument.cookie", "window.locat&#x69;on", "in&#x6e;erHTML",
            "fromCh&#x61;rCode(", "encodeURICompone&#x6e;t(", "setTim&#x65;out(", "setInt&#x65;rval(",
            "xhr.op&#x65;n(", "xhr.se&#x6e;d(", "parent.fr&#x61;mes[", "prom&#x70;t(", "confirm(",
            "formD&#x61;ta.append(", "<img src=", "<audio src=",
            # XSS attack keywords
            "<script>", "<script", "alert(", "onmouseover", "onload", "onclick", "onerror",
            "eval(", "document.cookie", "window.location", "innerHTML", "fromCharCode(",
            "encodeURIComponent(", "setTimeout(", "setInterval(", "xhr.open(", "xhr.send(",
            "parent.frames[", "prompt(", "confirm(", "formData.append(", "<img src=",
            "<audio src=", "<video src=", "<svg/onload=", "<marquee>", "<input type=\"text\" value=",
            "<a href=", "<link href=", "<iframe src=", "<body onload=", "<meta http-equiv=",
            "<form action=", "<textarea>", "<object data=", "<embed src=", "<style>", "<xss>", "<noscript>",
            "<applet>", "<base href=", "<s&#99;ript>", "al&#x65;rt(", "onmo&#x75;seover", "o&#x6e;load",
            "onclic&#x6b;", "onerror", "e&#x76;al(", "do&#x63;ument.cookie", "window.locat&#x69;on",
            "in&#x6e;erHTML", "fromCh&#x61;rCode(", "encodeURICompone&#x6e;t(", "setTim&#x65;out(",
            "setInt&#x65;rval(", "xhr.op&#x", "xhr.send(", "parent.fra&#x6d;es[", "pro&#x6d;pt(", "con&#x66;irm(", "formD&#x61;ta.append(",
            "<img s&#x72;c=", "<audio s&#x72;c=", "<video s&#x72;c=", "<svg/onload=", "<ma&#x72;quee>",
            "<inpu&#x74; type=\"text\" value=", "<a hre&#x66;=", "<link hre&#x66;=", "<iframe s&#x72;c=",
            "<body onl&#x6f;ad=", "<meta http-equiv=", "<form action=", "<texta&#x72;ea>", "<ob&#x6a;ect data=",
            "<embed s&#x72;c=", "<style>", "<xss>", "<noscript>", "<applet>", "<base href=", "<s&#99;ript>",
            # SQL injection keywords
            "OR", "AND", "--", ";", "SELECT", "FROM", "WHERE", "INSERT", "UPDATE", "DELETE", "EXECUTE", "UNION",
            "JOIN", "DROP", "CREATE", "ALTER", "TRUNCATE", "TABLE", "DATABASE", "HAVING", "LIKE", "ESCAPE",
            "ORDER BY", "GROUP BY", "LIMIT", "OFFSET", "XOR", "NOT", "BETWEEN", "IN", "EXISTS", "OR 1=1", "AND 1=1",
            "--", ";", "'", "\"", "`", "/**/", "/*!*/", "/*...*/", "|", "^",
            # "&",
            "; SELECT * FROM users WHERE username='admin' --", "1'; DROP TABLE users; --",
            "UNION SELECT 1,2,3,4,5,6,7,8,9,10 FROM users WHERE username='admin'",
            "SELECT * FROM users WHERE id = 1 OR 1=1", "SELECT * FROM users WHERE username='admin' AND password='password'",
            "SELECT * FROM users WHERE username LIKE '%admin%'", "SELECT * FROM users WHERE username IN ('admin', 'user', 'guest')",
            "SELECT * FROM users WHERE EXISTS (SELECT * FROM admin_users WHERE username='admin')",
            "SELECT * FROM users WHERE password=MD5('password')", "SELECT * FROM users WHERE password=SHA1('password')",
            "SELECT * FROM users WHERE password=SHA2('password', 256)", "SELECT * FROM users WHERE password=PASSWORD('password')",
            # XSS keywords
            "<sc&#x72;ipt>", "<img onerror=", "<svg/onload=alert(", "<audio onloadedmetadata=",
            "<video onloadedmetadata=", "<iframe srcdoc=", "<form onsubmit=alert(", "<object type=text/html data=",
            "<applet codebase=", "<link rel=", "<base href=", "<meta charset=", "<textarea onfocus=",
            "<body onload=", "<input type=\"text\" value=\"", "<a href=", "<embed src=", "<style>",
            "<script>alert('xss')</script>", "<img src=x onerror=alert('xss')>", "<body onload=alert('xss')>",
            "<a href=\"javascript:alert('xss')\">Click Here</a>", "<iframe src=\"javascript:alert('xss')\"></iframe>",
            "<script>alert(String.fromCharCode(88,83,83))</script>", "<input value=\"\" onclick=alert('xss')>",
            # SQL injection keywords
            "AND 1=1", "OR 1=1", "AND 1=2", "OR 1=2", "SELECT COUNT(*) FROM", "SELECT * FROM users WHERE",
            "SELECT * FROM users ORDER BY", "SELECT * FROM users LIMIT", "SELECT * FROM users OFFSET",
            "SELECT * FROM users WHERE 1=1", "SELECT * FROM users WHERE 1=0", "SELECT * FROM users WHERE id=",
            "SELECT * FROM users WHERE username=", "SELECT * FROM users WHERE password=",
            "SELECT * FROM users WHERE email=", "SELECT * FROM users WHERE status=",
            "SELECT * FROM users WHERE role=", "SELECT * FROM users WHERE access_token=",
            "SELECT * FROM users WHERE refresh_token=", "SELECT * FROM users WHERE session_id=",
            "INSERT INTO users (id, username, password, email, status, role, access_token, refresh_token, session_id) VALUES",
            "UPDATE users SET", "DELETE FROM users WHERE id=", "DROP TABLE", "DROP DATABASE",
            "CREATE DATABASE", "CREATE TABLE", "ALTER TABLE", "TRUNCATE TABLE", "UNION SELECT",
            "HAVING 1=1", "HAVING 1=0", "LIKE '%", "LIKE '%admin%'", "/.."
        )
        p = (sum(url.count(x) for x in xss_and_sql_keywords))
        suspicious += p
        return (p)

    df['iocs_count'] = df['URL'].apply(lambda i: iocs(i))

    del df['is_short_url']
    del df['hostname_length']
    X = df[['period_count', 'www_count', 'at_count', 'directory_count', 'embedded_domain_count',
            'less_than_count', 'open_brace_count', 'close_brace_count', 'plus_count',
            'minus_count', 'double_quote_count', 'colon_count', 'semicolon_count',
            'asterisk_count', 'backtick_count', 'tilde_count', 'ampersand_count',
            'exclamation_count', 'digit_count', 'special_char_count', 'percent_count',
            'question_mark_count', 'equal_sign_count', 'url_length', 'iocs_count']]

    import pickle

    def lgb_model_prediction(X):
        with open('models/lgb_model.pkl', 'rb') as f:
            lgb_model = pickle.load(f)
        y_pred_lgb = lgb_model.predict(X)
        return y_pred_lgb

    # Load XGBoost model
    def xgb_model_prediction(X):
        with open('models/xgboost_model.pkl', 'rb') as f:
            xgb_model = pickle.load(f)
        y_pred_xgb = xgb_model.predict(X)
        return y_pred_xgb
    # Load Gradient Boosting model

    def gbdt_model_prediction(X):
        with open('models/gbdt_model.pkl', 'rb') as f:
            gbdt_model = pickle.load(f)
        y_pred_gbdt = gbdt_model.predict(X)
        return y_pred_gbdt

    # Load random forest model
    def rf_model_prediction(X):
        with open('models/random_forest_model.pkl', 'rb') as f:
            rf_model = pickle.load(f)
        y_pred_rf = rf_model.predict(X)
        return y_pred_rf

    y_pred_lgb = lgb_model_prediction(X)

    y_pred_xgb = xgb_model_prediction(X)

    y_pred_gbdt = gbdt_model_prediction(X)
    y_pred_rf = rf_model_prediction(X)

    # print("lgb predictions: ", y_pred_lgb)
    # print("XGBoost predictions: ", y_pred_xgb)
    # print("gdbt predictions: ", y_pred_gbdt)
    # print("random forest: ", y_pred_rf)

    print(suspicious)
    y_pred_xgb_cookie = 1 if y_pred_xgb_cookie == 0 else 0
    # assuming y_pred_lgb, y_pred_xgb, and y_pred_gbdt are arrays of 0s and 1s
    confidences = (y_pred_lgb + y_pred_xgb + y_pred_gbdt +
                   y_pred_rf + (y_pred_xgb_cookie*0.10)) / 4.0
    average_confidence = confidences.mean()

    if (average_confidence < 0.5) and (suspicious == 0):
        print("Benign")
        return "Benign"
    else:
        print("Malicious")
        return "Malicious"


@api_view(['POST'])
def hello(request):
    # Get the URL from the JSON payload
    list = request.data
    # print(list)
    print(type(list))
    return Response(model_predictions_all(list))
