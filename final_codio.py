from flask import Flask, request, abort
from sqlalchemy import text
from flask_sqlalchemy import SQLAlchemy
import logging
from sklearn.metrics.pairwise import cosine_similarity
from sklearn.model_selection import train_test_split
from joblib import dump, load
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:pearl09@localhost/sqlDB'
db = SQLAlchemy(app)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# valid_handler = logging.FileHandler('valid_ips.log')
# valid_handler.setLevel(logging.INFO)
# valid_handler.setFormatter(logging.Formatter('%(asctime)s - VALID - %(message)s'))
# logger.addHandler(valid_handler)

block_handler = logging.FileHandler('blocked_ips.log')
block_handler.setLevel(logging.WARNING)
block_handler.setFormatter(logging.Formatter('%(asctime)s - BLOCKED - %(message)s'))
logger.addHandler(block_handler)

if os.path.isfile('classifier.joblib'):
    print("I'm in if cond")
    clf = load('classifier.joblib')
    vectorizer = load('vectorizer.joblib')
    with open(r"C:\Users\Ruma Ghosh\OneDrive\Desktop\sql\data.txt", 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    texts, labels = [], []
    for line in data:
        temp = line.split(",")
        text = temp[0]
        label = temp[1]
        if (label == '0'or label=='1'):
            texts.append(text)
            labels.append(label)
    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)
                
    vectorizer2 = TfidfVectorizer(max_df=0.85, stop_words='english')
    text_vectorized = vectorizer2.fit_transform(X_train)
else:
    print("I'm in else cond")
    with open(r"C:\Users\Ruma Ghosh\OneDrive\Desktop\sql\data.txt", 'r', encoding='utf-8') as f:
        data = f.read().splitlines()

    texts, labels = [], []
    for line in data:
        temp = line.split(",")
        text = temp[0]
        label = temp[1]
        if (label == '1' or label == '0'):
            texts.append(text)
            labels.append(label)

    X_train, X_test, y_train, y_test = train_test_split(texts, labels, test_size=0.2, random_state=42)

    vectorizer = TfidfVectorizer(max_df=0.85, stop_words='english')
    X_train_vectorized = vectorizer.fit_transform(X_train)
#working on model
    clf = RandomForestClassifier(random_state=42)
    clf.fit(X_train_vectorized, y_train)

    X_test_vectorized = vectorizer.transform(X_test)

    y_pred = clf.predict(X_test_vectorized)

    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy}")
#saving the train model
    dump(clf, 'classifier.joblib')
    dump(vectorizer, 'vectorizer.joblib')


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), unique=True, nullable=False)

    def __repr__(self):
        return '<User %r>' % self.name


@app.route('/', methods=['GET', 'POST'])
def index():
    global vectorizer
    if request.method == 'POST':
        user_input = request.form['user_input']
        password = request.form['password']

        query = str(user_input+password)
        query_vector = vectorizer.transform([query])#vectorizing the user query
        is_malicious = clf.predict(query_vector)#after vectorising check malicious
        if is_malicious==['1']:
            logger.error(f"Blocked request from IP {request.remote_addr} to URL {request.url}: {query}")
            # block_handler.warning(query)
            print("it is malicious")
            with open('blocked_ips.log', 'a') as f:
                f.write(request.remote_addr + '\n')
            return "Request Blocked"
#if not malicious
        print("valid request")
        cosine_similarities = cosine_similarity(query_vector, text_vectorized).flatten()
        most_similar_query_index = cosine_similarities.argsort()[-1]
        similarity_score = cosine_similarities[most_similar_query_index]
#if userinput is not match with dataset
        if similarity_score >= 0.6:
            print("checking the similaerty")
            logger.error(f"Blocked request from IP {request.remote_addr} to URL {request.url}: {query}")
            # block_handler.warning(query)
            with open('blocked_ips.log', 'a') as f:
                f.write(request.remote_addr + '\n')
            similarity_percentage = round(similarity_score * 100, 2)
            return f"Request Blocked. Query similarity percentage: {similarity_percentage}%"
        else:
            # logger.info(f"Valid request from IP {request.remote_addr} to URL {request.url}")
            # with open('valid_ips.log', 'a') as f:
            #     f.write(request.remote_addr + '\n')
            similarity_percentage = round(similarity_score * 100, 2)
            return f"Request successfully processed. Query similarity percentage: {similarity_percentage}%"

    return '''

<html>
<head>
  <title>SQL Injection Detection and Prevention Using Artificial Intelligence</title>
  <style>
    body {
      background: url(https://rare-gallery.com/uploads/posts/1012591-hacking-hackers-darkness-black-and-white-monochrome-photography.jpg) no-repeat center center fixed;
    background-size: cover;
    background-position: center;
    }
    
    h1 {
        text-align: center;
        color: yellow;
      font-size: 2em;
      margin-top: 0;
    }
    
    h2 {
        text-align: center;
        color: white;
      font-size: 1.5em;
      margin-top: 10px;
    }
    
    p {
      font-size: 20px;
        color: white;
      margin-bottom: 10px;
    }
    
    .container {
      max-width: 800px;
      margin: 0 auto;
    }
    
    .form-group {
        font-size: 20px;
        color: white;
        margin-bottom: 10px;
    }
    
    input {
      color: black;
      width: 100%;
      padding: 8px;
      border: 1px solid #ccc;
      border-radius: 5px;
    }
    
    button {
      background-color: #333;
      color: #fff;
      padding: 12px 24px;
      border: none;
      border-radius: 5px;
      font-size: 16px;
      cursor: pointer;
    }
    
    .alert {
      margin-top: 20px;
      padding: 10px;
      background-color: #f44336;
      color: #fff;
      font-weight: bold;
    }
    
    .success {
      background-color: #008000;
    }
    
    .danger {
      background-color: #d9534f;
    }
  </style>
</head>
<body>
  <div class="container">
    <h1>SQL Injection Detection and Prevention Using <br> Artificial Intelligence</h1>
    <br><br>
    <h2>-: Introduction :-</h2>
    <p>The internet has become an essential part of our daily lives. We use it for everything from communication and entertainment to shopping and banking. However, this increased reliance on the internet has also made us more vulnerable to cyber threats. It detects and responds to threats after they have already occurred. This can be a problem because it can allow attackers to cause significant damage before the security software is able to stop them. Machine learning-based approaches are gaining popularity for their ability to detect and prevent cyber threats proactively. This is because machine learning algorithms can learn to identify patterns in data that are indicative of malicious activity. This allows them to detect threats before they occur, which can help to prevent damage.</p>
    <br><br>
    <h2>-: Working Process :-</h2>
    <p>This is a Flask application  that serves a machine learning model that classifies user 
queries as either malicious or not.

The app first checks if the model and vectorizer have already been trained and saved in the file system, and loads them if they exist. Otherwise, it trains a new model on a labeled dataset and saves it to disk.

When a request is received at the root URL, the app expects the user to submit a form 
with two inputs. 
The application first checks if the user input is malicious by predicting its label with the loaded or trained model. If the predicted label is true, the app blocks the request and logs the event to a file. 

Otherwise, the app computes the similarity between the user input and the training data if the similarity is above 60%,  it blocks the request and logs the event to same file 

if the similarity is below the 60% then log the event in another file.. Finally, the app returns a response indicating whether the request was blocked or processed successfully.


The model achieved a high accuracy of 0.8297, indicating that it correctly 
predicted 82.97% of the cases. The precision of 0.7051 suggests that when the model 
predicted a sample as positive, it was correct 70.51% of the time. The sensitivity of 0.9880 indicates that the model successfully identified 98.80% of the actual positive cases. The F1 score of 0.8229 combines precision and recall into a single metric, providing a balanced evaluation of the model's performance. 

The confusion matrix shows that the model had 181 true positives (correctly predicted 
positive samples) and 165 true negatives (correctly predicted negative samples). 
However, it also had 69 false positives (incorrectly predicted positive samples) and 2 
false negatives (incorrectly predicted negative samples).



</p><br><br>
    <h2>   - : SQL Injection Detector : -   </h2>
    <p>This application uses artificial intelligence to detect SQL injection attacks. The application trains a machine learning model on a dataset of malicious and benign SQL queries. The model is then used to classify new queries as malicious or benign.</p>
    <form method="post">
      <div class="form-group">
        <br>
        <label for="user_input">Enter User name: </label>
        <br>
        <input type="text" id="user_input" name="user_input" placeholder="User input">
        <br><br>
        <label for="password">Enter Password: </label>
        <br>
        <input type="text" id="password" name="password" placeholder="Password"><br>
      </div>
      <button type="submit">Login</button>
    </form>
    <div class="alert"></div>
  </div>
</body>
</html>
        '''


if __name__ == '__main__':
    app.run(debug=True)