output "node_public_ip" {
  description = "Elastic IP of the k3s node"
  value       = aws_eip.node.public_ip
}

output "ssh_command" {
  description = "How to reach the node"
  value       = "ssh ubuntu@${aws_eip.node.public_ip}"
}
