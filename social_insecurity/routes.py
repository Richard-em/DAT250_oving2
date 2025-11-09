"""Provides all routes for the Social Insecurity application.

This file contains the routes for the application. It is imported by the social_insecurity package.
It also contains the SQL queries used for communicating with the database.
"""

from pathlib import Path
from flask import current_app as app, flash, redirect, render_template, request, send_from_directory, url_for
from flask_login import current_user, login_user, logout_user, login_required
from social_insecurity import sqlite, bcrypt, login
from social_insecurity.forms import IndexForm, PostForm, CommentsForm, FriendsForm, ProfileForm
from social_insecurity.user import User

@login.user_loader
def load_user(user_id):
    query = "SELECT * FROM Users WHERE id = ?;"
    user = sqlite.query(query, user_id, one=True)
    if user:
        return User(user["id"], user["username"], user["password"])
    return None
def register_routes(app):
    @app.route("/", methods=["GET", "POST"])
    @app.route("/index", methods=["GET", "POST"])
    def index():
        """Provides the index page for the application.

        It reads the composite IndexForm and based on which form was submitted,
        it either logs the user in or registers a new user.

        If no form was submitted, it simply renders the index page.
        """
        index_form = IndexForm()
        login_form = index_form.login
        register_form = index_form.register
        
        if login_form.validate_on_submit() and login_form.submit.data:
            user = User.get_by_username(login_form.username.data)

            if not user:
                flash("Sorry, this user does not exist!", category="warning")
            elif not bcrypt.check_password_hash(user.password, login_form.password.data):
                flash("Sorry, wrong password!", category="warning")
            else:
                login_user(user, remember=login_form.remember_me.data)
                return redirect(url_for("stream", username=login_form.username.data))

        elif register_form.validate_on_submit() and register_form.submit.data:
            existing = User.get_by_username(register_form.username.data)
            if existing:
                flash("Username taken", category="warning")
            else:
                hashed_pw = bcrypt.generate_password_hash(register_form.password.data).decode("utf-8")
                sqlite.query(
                    "INSERT INTO Users (username, first_name, last_name, password) VALUES (?, ?, ?, ?);",
                    register_form.username.data,
                    register_form.first_name.data,
                    register_form.last_name.data,
                    hashed_pw,
                )
                return redirect(url_for("index"))

        return render_template("index.html.j2", title="Welcome", form=index_form)
    
    @app.route("/logout")
    @login_required
    def logout():
        logout_user()
        return redirect(url_for("index"))

    @app.route("/stream/<string:username>", methods=["GET", "POST"])
    @login_required
    def stream(username: str):
        """Provides the stream page for the application.

        If a form was submitted, it reads the form data and inserts a new post into the database.

        Otherwise, it reads the username from the URL and displays all posts from the user and their friends.
        """
        if username != current_user.username:
            return redirect(url_for("stream", username=current_user.username))
        post_form = PostForm()
        user = User.get_by_username(current_user.username)

        if post_form.validate_on_submit():
            filename = ""
            if post_form.image.data:
                path = Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"] / post_form.image.data.filename
                post_form.image.data.save(path)
                filename = post_form.image.data.filename

            sqlite.query(
                "INSERT INTO Posts (u_id, content, image, creation_time) VALUES (?, ?, ?, CURRENT_TIMESTAMP);",
                user.id, post_form.content.data, filename
            )
            return redirect(url_for("stream", username=username))

        posts = sqlite.query("""
            SELECT p.*, u.*, (SELECT COUNT(*) FROM Comments WHERE p_id = p.id) AS cc
            FROM Posts AS p
            JOIN Users AS u ON u.id = p.u_id
            WHERE p.u_id IN (SELECT u_id FROM Friends WHERE f_id = ?)
                OR p.u_id IN (SELECT f_id FROM Friends WHERE u_id = ?)
                OR p.u_id = ?
            ORDER BY p.creation_time DESC;
        """, user.id, user.id, user.id)
        
        return render_template("stream.html.j2", title="Stream", username=username, form=post_form, posts=posts)


    @app.route("/comments/<string:username>/<int:post_id>", methods=["GET", "POST"])
    def comments(username: str, post_id: int):
        """Provides the comments page for the application.

        If a form was submitted, it reads the form data and inserts a new comment into the database.

        Otherwise, it reads the username and post id from the URL and displays all comments for the post.
        """
        comments_form = CommentsForm()
        get_user = f"""
            SELECT *
            FROM Users
            WHERE username = '{username}';
            """
        user = sqlite.query(get_user, one=True)

        if comments_form.validate_on_submit():
            insert_comment = f"""
                INSERT INTO Comments (p_id, u_id, comment, creation_time)
                VALUES ({post_id}, {user["id"]}, '{comments_form.comment.data}', CURRENT_TIMESTAMP);
                """
            sqlite.query(insert_comment)

        get_post = f"""
            SELECT *
            FROM Posts AS p JOIN Users AS u ON p.u_id = u.id
            WHERE p.id = {post_id};
            """
        get_comments = f"""
            SELECT DISTINCT *
            FROM Comments AS c JOIN Users AS u ON c.u_id = u.id
            WHERE c.p_id={post_id}
            ORDER BY c.creation_time DESC;
            """
        post = sqlite.query(get_post, one=True)
        comments = sqlite.query(get_comments)
        return render_template(
            "comments.html.j2", title="Comments", username=username, form=comments_form, post=post, comments=comments
        )


    @app.route("/friends/<string:username>", methods=["GET", "POST"])
    @login_required
    def friends(username: str):
        """Provides the friends page for the application.

        If a form was submitted, it reads the form data and inserts a new friend into the database.

        Otherwise, it reads the username from the URL and displays all friends of the user.
        """
        if username != current_user.username:
            return redirect(url_for("friends", username=current_user.username))
        me = User.get_by_username(current_user.username)
        form = FriendsForm()

        if form.validate_on_submit():
            friend = sqlite.query("SELECT * FROM Users WHERE username = ?;", form.username.data, one=True)

            if friend is None:
                flash("User does not exist!", category="warning")
            elif friend["id"] == me.id:
                flash("You cannot be friends with yourself!", category="warning")
            else:
                already = sqlite.query(
                    "SELECT 1 FROM Friends WHERE u_id = ? AND f_id = ?;",
                    me.id, friend["id"], one=True
                )
                if already:
                    flash("You are alreadyt friends with user", category="warning")
                else:
                    sqlite.query(
                        "INSERT INTO Friends (u_id, f_id) VALUES (?, ?)",
                        me.id, friend["id"]
                    )
                    flash("Friend successfully added")
            return redirect(url_for("friends", username=current_user.username))
        
        friends = sqlite.query(
            """
            SELECT u.*
            FROM Friends AS f
            JOIN Users  AS u ON f.f_id = u.id
            WHERE f.u_id = ? AND f.f_id != ?
            """,
            me.id, me.id
        )

        return render_template("friends.html.j2", title="Friends", username=username, friends=friends, form=form)


    @app.route("/profile/<string:username>", methods=["GET", "POST"])
    @login_required
    def profile(username: str):
        """Provides the profile page for the application.

        If a form was submitted, it reads the form data and updates the user's profile in the database.

        Otherwise, it reads the username from the URL and displays the user's profile.
        """
        if username != current_user.username:
            return redirect(url_for("profile", username=current_user.username))
        user = User.get_by_username(current_user.username)
        profile_form = ProfileForm()

        if profile_form.validate_on_submit():
            update_profile = f"""
                UPDATE Users
                SET education='{profile_form.education.data}', employment='{profile_form.employment.data}',
                    music='{profile_form.music.data}', movie='{profile_form.movie.data}',
                    nationality='{profile_form.nationality.data}', birthday='{profile_form.birthday.data}'
                WHERE username='{username}';
                """
            sqlite.query(update_profile)
            return redirect(url_for("profile", username=current_user.username))

        return render_template("profile.html.j2", title="Profile", username=current_user.username, user=user, form=profile_form)


    @app.route("/uploads/<string:filename>")
    def uploads(filename):
        """Provides an endpoint for serving uploaded files."""
        return send_from_directory(Path(app.instance_path) / app.config["UPLOADS_FOLDER_PATH"], filename)
