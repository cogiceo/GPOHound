class GroupMembershipProcessor:
    """Process Group Membership"""

    def __init__(self, ad_utils=None):
        self.ad_utils = ad_utils

    def process(self, settings, domain_sid):
        """
        Extract the "Group Membership" settings that will be applied to a computer
        Output the settings applied to group and there impact on previous setting :
        - "Members" is processed first : "Members" delete the previous group members
        - "MemberOf" is processed second : "MemberOf" add group member
        """

        output = []
        members_of = {}

        # Extract "Members" settings
        for group, membership in settings.items():
            if group.startswith("*"):
                sid = group.strip("*")
                name = self.ad_utils.get_trustee(sid).get("name")
                group_dict = {"sid": sid, "name": name}
            else:
                sid = self.ad_utils.get_trustee(group, domain_sid).get("sid")
                group_dict = {"sid": sid, "name": group}

            members = []
            for member in membership.get("Members", []):
                if member:
                    if member.startswith("*"):
                        sid = member.strip("*")
                        name = self.ad_utils.get_trustee(sid).get("name")
                        members.append({"sid": sid, "name": name, "action": "ADD"})
                    else:
                        sid = self.ad_utils.get_trustee(member, domain_sid).get("sid")
                        members.append({"sid": sid, "name": member, "action": "ADD"})

            if members:
                output.append(
                    {
                        "Group": group_dict,
                        "Members": members,
                        "Action": "REPLACE",
                        "DeleteUsers": True,
                        "DeleteGroups": True,
                    }
                )

            # Extract "MemberOf" settings
            for member_of in membership.get("Memberof", []):
                if member_of:
                    members_of.setdefault(member_of, []).append(group)

        # Unified output for "MemberOf" settings
        if members_of:
            for group, members in members_of.items():

                if group.startswith("*"):
                    sid = group.strip("*")
                    name = self.ad_utils.get_trustee(sid).get("name")
                    parsed_group = {"sid": sid, "name": name}
                else:
                    sid = self.ad_utils.get_trustee(group, domain_sid).get("sid")
                    parsed_group = {"sid": sid, "name": group}

                parsed_members = []
                for member in members:

                    if member.startswith("*"):
                        sid = member.strip("*")
                        name = self.ad_utils.get_trustee(sid).get("name")
                        parsed_members.append({"sid": sid, "name": name, "action": "ADD"})
                    else:
                        sid = self.ad_utils.get_trustee(member, domain_sid).get("sid")
                        parsed_members.append({"sid": sid, "name": member, "action": "ADD"})

                if parsed_members and parsed_group:
                    output.append(
                        {
                            "Group": parsed_group,
                            "Members": parsed_members,
                            "Action": "UPDATE",
                            "DeleteUsers": False,
                            "DeleteGroups": False,
                        }
                    )

        return output
