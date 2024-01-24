from flask import Flask
from EasyOIDC import Config, SessionHandler
from EasyOIDC.frameworks.taipy import TaipyOIDClient
from taipy import Gui
import taipy.gui.builder as tgb
from taipy.gui import Markdown

app = Flask(__name__)
session_storage = SessionHandler(mode='redis', namespace=__name__)
auth_config = Config('.env')
auth = TaipyOIDClient(app, auth_config=auth_config, session_storage=session_storage)


with tgb.Page() as home_page:
    tgb.text("Name:")
    tgb.input("{input_name}")
    tgb.button("Submit")
    tgb.text("Message {message}")


pages = {
    "page1": Markdown("#HolaPage1"),
	"page2": Markdown("#HolaPage2"),
    "/": Markdown("<center><|navbar|></center>")
}

gui = Gui(pages=pages, flask=app)
gui.run()