#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_RULES 10
#define MAX_IP_LENGTH 16

struct rule {
  char source_ip[MAX_IP_LENGTH];
  char destination_ip[MAX_IP_LENGTH];
  int source_port;
  int destination_port;
  int action;
};

struct firewall {
  struct rule rules[MAX_RULES];
  int num_rules;
};

void init_firewall(struct firewall *firewall) {
  firewall->num_rules = 0;
}

void add_rule(struct firewall *firewall, char *source_ip, char *destination_ip,
               int source_port, int destination_port, int action) {
  if (firewall->num_rules >= MAX_RULES) {
    printf("Firewall is full.\n");
    return;
  }

  strncpy(firewall->rules[firewall->num_rules].source_ip, source_ip, MAX_IP_LENGTH - 1);
  firewall->rules[firewall->num_rules].source_ip[MAX_IP_LENGTH - 1] = '\0';
  strncpy(firewall->rules[firewall->num_rules].destination_ip, destination_ip, MAX_IP_LENGTH - 1);
  firewall->rules[firewall->num_rules].destination_ip[MAX_IP_LENGTH - 1] = '\0';
  firewall->rules[firewall->num_rules].source_port = source_port;
  firewall->rules[firewall->num_rules].destination_port = destination_port;
  firewall->rules[firewall->num_rules].action = action;
  firewall->num_rules++;
}

int check_rule(struct firewall *firewall, char *source_ip, char *destination_ip,
               int source_port, int destination_port) {
  for (int i = 0; i < firewall->num_rules; i++) {
    if (strcmp(firewall->rules[i].source_ip, source_ip) == 0 &&
        strcmp(firewall->rules[i].destination_ip, destination_ip) == 0 &&
        firewall->rules[i].source_port == source_port &&
        firewall->rules[i].destination_port == destination_port) {
      return firewall->rules[i].action;
    }
  }

  return -1;
}

void clear_input_buffer() {
  int c;
  while ((c = getchar()) != '\n' && c != EOF) {}
}

void print_menu() {
  printf("\n----- Firewall Menu -----\n");
  printf("1. Add Rule\n");
  printf("2. Check Packet\n");
  printf("3. Exit\n");
  printf("--------------------------\n");
}

int get_menu_choice() {
  int choice;
  printf("Enter your choice: ");
  scanf("%d", &choice);
  clear_input_buffer();
  return choice;
}

void get_string_input(const char *prompt, char *input, int max_length) {
  printf("%s: ", prompt);
  fgets(input, max_length, stdin);
  input[strcspn(input, "\n")] = '\0'; // Remove newline character from input
}

int get_integer_input(const char *prompt) {
  int input;
  printf("%s: ", prompt);
  scanf("%d", &input);
  clear_input_buffer();
  return input;
}

int main() {
  struct firewall firewall;
  init_firewall(&firewall);

  int choice;
  char source_ip[MAX_IP_LENGTH];
  char destination_ip[MAX_IP_LENGTH];
  int source_port, destination_port, action;

  do {
    print_menu();
    choice = get_menu_choice();

    switch (choice) {
      case 1:
        get_string_input("Enter source IP", source_ip, MAX_IP_LENGTH);
        get_string_input("Enter destination IP", destination_ip, MAX_IP_LENGTH);
        source_port = get_integer_input("Enter source port");
        destination_port = get_integer_input("Enter destination port");
        action = get_integer_input("Enter action (1 for allow, 0 for block)");

        add_rule(&firewall, source_ip, destination_ip, source_port, destination_port, action);
        printf("Rule added successfully.\n");
        break;

      case 2:
        get_string_input("Enter source IP", source_ip, MAX_IP_LENGTH);
        get_string_input("Enter destination IP", destination_ip, MAX_IP_LENGTH);
        source_port = get_integer_input("Enter source port");
        destination_port = get_integer_input("Enter destination port");

        int packet_action = check_rule(&firewall, source_ip, destination_ip, source_port, destination_port);
        if (packet_action == 1) {
          printf("Packet allowed.\n");
          add_rule(&firewall, source_ip, "", 0, 0, 0);  // Blocking the source IP
        } else if (packet_action == 0) {
          printf("Packet blocked.\n");
        } else {
          printf("No matching rule found. Packet denied.\n");
        }
        break;

      case 3:
        printf("Exiting...\n");
        break;

      default:
        printf("Invalid choice. Please try again.\n");
        break;
    }
  } while (choice != 3);

  return 0;
}
