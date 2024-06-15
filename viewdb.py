from weightApp import app, db, User


def print_users():
    with app.app_context():
        users = User.query.all()
        for user in users:
            print(
                f'ID: {user.id}, Username: {user.username}, Email: {user.email}, Password: {user.password}')


if __name__ == "__main__":
    print_users()
