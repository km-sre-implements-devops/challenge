from app import app, db


welcome = """

                                |\__/|
        Welcome                /     \ 
        to shield             /_.~ ~,_\ 
                                 \@/

        #################################
        #          written by           #
        #    k.michael@protonmail.ch    #
        ################################# 

"""


if __name__ == "__main__":
    db.create_all()
    app.run(debug=True, port=8080, host='0.0.0.0')