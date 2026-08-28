import torch

net = torch.load("model.pt")
net.eval()
net.train()
