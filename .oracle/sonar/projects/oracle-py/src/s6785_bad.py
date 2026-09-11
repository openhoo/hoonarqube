import graphene
from flask_sqlalchemy import SQLAlchemy
from graphql_server.flask import GraphQLView

db = SQLAlchemy()


class Record(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    parent_id = db.Column(db.Integer, db.ForeignKey("record.id"))
    parent = db.relationship("Record", remote_side=[id], backref="children")



class Node(graphene.ObjectType):
    child = graphene.Field(lambda: Node)


class Query(graphene.ObjectType):
    node = graphene.Field(Node)


schema = graphene.Schema(query=Query)
view = GraphQLView.as_view("api", schema=schema)
