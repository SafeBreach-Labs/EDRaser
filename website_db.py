from flask import Flask, render_template
from flask import request
from database import *

app = Flask(__name__, template_folder="./website_db/templates")
remote_db = None


@app.route('/',methods=['POST','GET'])
def index():
    if request.method == 'POST':
        user_dict = dict(request.form)
        try:
            remote_db.insert(SAMPLE_TABLE_NAME, user_dict)
        except Exception as e:
            logging.error(e)
    return render_template('index.html')
        
@app.route('/view_data',methods=['GET'])
def getdata():
    data = remote_db.fetch_data()
    return render_template('view_db.html', data=data)


def run_web_server(DB_server_ip: str, db_type: str, port: int, db_username: str, db_password: str, table_name: str):
    global remote_db
    table_name = table_name or SAMPLE_TABLE_NAME
    
    remote_db = Database(db_type, DB_server_ip, port, db_username, db_password)
    remote_db.connect()

    if not remote_db.is_database_exists(SAMPLE_DB_NAME):
        remote_db.create_sample_database()

    if not remote_db.is_table_exists(table_name):
        remote_db.create_table(table_name, {'fname': 'VARCHAR(1024)', 'username': 'VARCHAR(1024)', 'password': 'VARCHAR(1024)'})


    remote_db.set_table(table_name)

    app.run('0.0.0.0',port=8080)
    