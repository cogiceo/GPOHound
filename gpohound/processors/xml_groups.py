class XMLGroupsProcessor:

    def __init__(self, ad_utils):
        self.ad_utils = ad_utils
        self.action_type = {"D": "DELETE", "U": "UPDATE", "C": "CREATE", "R": "REPLACE"}

    def process(self, settings, domain_sid):
        """
        Output the settings applied to group and there impact on previous setting.
        The groups settings are processed based on the order define in the preference settings,
        Order 1 is processed first, order 2 is processed second...
        """

        if settings.get("Group"):
            output = []
            groups = settings.get("Group")
            if isinstance(groups, dict):
                groups = [groups]

            for group in groups:
                properties = group.get("Properties")

                if properties.get("groupSid"):

                    sid = properties.get("groupSid")
                    if not properties.get("groupName"):
                        # If groupSid try to find the name
                        name = self.ad_utils.get_trustee(sid).get("name")
                    else:
                        name = properties.get("groupName")

                    group_dict = {"sid": sid, "name": name}

                elif properties.get("groupName"):
                    # If only groupName try to find the associated sid
                    name = properties.get("groupName")

                    if "\\" in name:
                        # If the name is in format NetbiosName\Username try to find name and sid
                        info = self.ad_utils.get_trustee(name)
                        name = info["name"]
                        sid = info["sid"]
                    else:
                        # Domain nme without the domain
                        sid = self.ad_utils.get_trustee(name, domain_sid).get("sid")
                    group_dict = {"sid": sid, "name": name}
                else:
                    continue

                # If the newName property is not empty then the group as a different name locally
                if properties.get("newName"):
                    group_dict["newname"] = properties.get("newName")

                if properties.get("userAction"):
                    group_dict["useraction"] = properties.get("userAction")

                action_type = self.action_type.get(properties.get("action"), "UPDATE")

                # DELETE group action
                if action_type and action_type == "DELETE":
                    if properties.get("groupSid"):
                        output.append({"Group": group_dict, "Action": "DELETE"})
                else:
                    # UPDATE setting is default if not set
                    if not action_type:
                        action_type = "UPDATE"

                    members_out = []

                    # Attributes that define if the users or groups need to be remove from the group
                    delete_users = True if properties.get("deleteAllUsers") == "1" else False
                    delete_groups = True if properties.get("deleteAllGroups") == "1" else False

                    if properties.get("Members"):

                        # Process the members
                        for members in properties.get("Members").values():
                            if isinstance(members, dict):
                                members = [members]

                            for member in members:
                                trustee = {"sid": None, "name": None}

                                if member.get("sid"):
                                    trustee["sid"] = member.get("sid")
                                    if member.get("name"):
                                        trustee["name"] = member.get("name")
                                    else:
                                        trustee["name"] = self.ad_utils.get_trustee(trustee["sid"]).get("name")

                                else:
                                    trustee["name"] = member.get("name")
                                    trustee["sid"] = self.ad_utils.get_trustee(trustee["name"], domain_sid).get("sid")

                                if trustee.get("sid") or trustee.get("name"):
                                    trustee["action"] = member.get("action")
                                    members_out.append(trustee)

                            if trustee:
                                output.append(
                                    {
                                        "Group": group_dict,
                                        "Members": members_out,
                                        "Action": action_type,
                                        "DeleteUsers": delete_users,
                                        "DeleteGroups": delete_groups,
                                    }
                                )
                    else:
                        output.append(
                            {
                                "Group": group_dict,
                                "Members": members_out,
                                "Action": action_type,
                                "DeleteUsers": delete_users,
                                "DeleteGroups": delete_groups,
                            }
                        )

            return output
        return None
