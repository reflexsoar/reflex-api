
# parsetab.py
# This file is automatically generated. Do not edit.
# pylint: disable=W,C,R
_tabversion = '3.10'

_lr_method = 'LALR'

_lr_signature = 'leftORleftANDnonassocEQUALSnonassocINnonassocCONTAINSrightSTRINGAND ARRAY BETWEEN BOOL CIDR CONTAINS EQUALS EWITH EXISTS FLOAT GT GTE IN IS LPAREN LT LTE MUTATOR NOT NUMBER OR REGEXP RPAREN STRING SWITH targetexpression : targetexpression : expression OR expressionexpression : expression AND expressionexpression : LPAREN expression RPARENexpression : LPAREN expression AND expression RPARENexpression : LPAREN expression OR expression RPARENexpression : target SWITH STRING\n                    | target MUTATOR SWITH STRING\n                    | target MUTATOR MUTATOR SWITH STRING\n                    | target MUTATOR MUTATOR MUTATOR SWITH STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING\n        expression : target EWITH STRING\n                    | target MUTATOR EWITH STRING\n                    | target MUTATOR MUTATOR EWITH STRING\n                    | target MUTATOR MUTATOR MUTATOR EWITH STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING\n        expression : target EQUALS STRING\n                    | target MUTATOR EQUALS STRING\n                    | target MUTATOR MUTATOR EQUALS STRING\n                    | target MUTATOR MUTATOR MUTATOR EQUALS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR EQUALS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EQUALS STRING\n                    | target EQUALS NUMBER\n                    | target NOT EQUALS STRING\n                    | target MUTATOR NOT EQUALS STRING\n                    | target MUTATOR MUTATOR NOT EQUALS STRING\n                    | target MUTATOR MUTATOR MUTATOR NOT EQUALS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR NOT EQUALS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT EQUALS STRING\n                    | target NOT EQUALS NUMBER\n        expression : target CONTAINS STRING\n                    | target MUTATOR CONTAINS STRING\n                    | target MUTATOR MUTATOR CONTAINS STRING\n                    | target MUTATOR MUTATOR MUTATOR CONTAINS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS STRING\n                    | target NOT CONTAINS STRING\n                    | target MUTATOR NOT CONTAINS STRING\n                    | target MUTATOR MUTATOR NOT CONTAINS STRING\n                    | target MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING\n                    | target CONTAINS ARRAY\n                    | target MUTATOR MUTATOR CONTAINS ARRAY\n                    | target MUTATOR MUTATOR MUTATOR CONTAINS ARRAY\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS ARRAY\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS ARRAY\n                    | target NOT CONTAINS ARRAY\n                    | target MUTATOR NOT CONTAINS ARRAY\n                    | target MUTATOR MUTATOR NOT CONTAINS ARRAY\n                    | target MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY\n                    | target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY\n        expression : target IN ARRAY\n                   | target MUTATOR IN ARRAY\n                   | target NOT IN ARRAY\n                   | target MUTATOR NOT IN ARRAY\n        expression : target GT NUMBER \n                   | target GTE NUMBER\n                   | target LT NUMBER\n                   | target LTE NUMBER\n                   | target MUTATOR GT NUMBER\n                   | target MUTATOR GTE NUMBER\n                   | target MUTATOR LT NUMBER\n                   | target MUTATOR LTE NUMBER\n                   | target GT FLOAT \n                   | target GTE FLOAT\n                   | target LT FLOAT\n                   | target LTE FLOAT\n                   | target MUTATOR GT FLOAT\n                   | target MUTATOR GTE FLOAT\n                   | target MUTATOR LT FLOAT\n                   | target MUTATOR LTE FLOAT\n                \n        expression : target CIDR STRING\n                    | target NOT CIDR STRING\n        expression : target EXISTS\n                    | target NOT EXISTS\n        expression : target REGEXP STRING\n                    | target NOT REGEXP STRING\n        expression : target IS BOOLexpression : target BETWEEN STRING\n                    | target NOT BETWEEN STRING\n        '
    
_lr_action_items = {'target':([0,3,4,5,63,64,],[2,2,2,2,2,2,]),'LPAREN':([0,3,4,5,63,64,],[3,3,3,3,3,3,]),'$end':([1,2,18,23,24,25,37,38,39,44,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,71,72,73,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,103,104,105,108,109,110,111,112,113,114,115,122,123,124,127,128,129,130,131,137,138,139,142,143,144,145,146,147,148,149,152,153,154,155,156,157,158,159,],[0,-1,-78,-2,-3,-7,-13,-19,-25,-79,-33,-45,-56,-60,-68,-61,-69,-62,-70,-63,-71,-76,-80,-82,-83,-4,-8,-14,-20,-34,-57,-64,-72,-65,-73,-66,-74,-67,-75,-26,-32,-39,-50,-58,-77,-81,-84,-9,-15,-21,-35,-46,-27,-40,-51,-59,-5,-6,-10,-16,-22,-36,-47,-28,-41,-52,-11,-17,-23,-37,-48,-29,-42,-53,-12,-18,-24,-38,-49,-30,-43,-54,-31,-44,-55,]),'OR':([1,2,18,22,23,24,25,37,38,39,44,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,71,72,73,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,103,104,105,108,109,110,111,112,113,114,115,122,123,124,127,128,129,130,131,137,138,139,142,143,144,145,146,147,148,149,152,153,154,155,156,157,158,159,],[4,-1,-78,64,-2,-3,-7,-13,-19,-25,-79,-33,-45,-56,-60,-68,-61,-69,-62,-70,-63,-71,-76,-80,-82,-83,-4,-8,-14,-20,-34,-57,-64,-72,-65,-73,-66,-74,-67,-75,-26,-32,-39,-50,-58,-77,-81,-84,-3,-2,-9,-15,-21,-35,-46,-27,-40,-51,-59,-5,-6,-10,-16,-22,-36,-47,-28,-41,-52,-11,-17,-23,-37,-48,-29,-42,-53,-12,-18,-24,-38,-49,-30,-43,-54,-31,-44,-55,]),'AND':([1,2,18,22,23,24,25,37,38,39,44,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,71,72,73,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,103,104,105,108,109,110,111,112,113,114,115,122,123,124,127,128,129,130,131,137,138,139,142,143,144,145,146,147,148,149,152,153,154,155,156,157,158,159,],[5,-1,-78,63,5,-3,-7,-13,-19,-25,-79,-33,-45,-56,-60,-68,-61,-69,-62,-70,-63,-71,-76,-80,-82,-83,-4,-8,-14,-20,-34,-57,-64,-72,-65,-73,-66,-74,-67,-75,-26,-32,-39,-50,-58,-77,-81,-84,-3,5,-9,-15,-21,-35,-46,-27,-40,-51,-59,-5,-6,-10,-16,-22,-36,-47,-28,-41,-52,-11,-17,-23,-37,-48,-29,-42,-53,-12,-18,-24,-38,-49,-30,-43,-54,-31,-44,-55,]),'RPAREN':([2,18,22,23,24,25,37,38,39,44,47,48,49,50,51,52,53,54,55,56,57,58,59,60,61,62,71,72,73,77,78,79,80,81,82,83,84,85,86,87,88,89,90,91,92,93,94,95,96,103,104,105,108,109,110,111,112,113,114,115,122,123,124,127,128,129,130,131,137,138,139,142,143,144,145,146,147,148,149,152,153,154,155,156,157,158,159,],[-1,-78,62,-2,-3,-7,-13,-19,-25,-79,-33,-45,-56,-60,-68,-61,-69,-62,-70,-63,-71,-76,-80,-82,-83,-4,-8,-14,-20,-34,-57,-64,-72,-65,-73,-66,-74,-67,-75,-26,-32,-39,-50,-58,-77,-81,-84,-3,-2,-9,-15,-21,-35,-46,-27,-40,-51,-59,-5,-6,-10,-16,-22,-36,-47,-28,-41,-52,-11,-17,-23,-37,-48,-29,-42,-53,-12,-18,-24,-38,-49,-30,-43,-54,-31,-44,-55,]),'SWITH':([2,7,26,65,97,116,],[6,27,66,98,117,132,]),'MUTATOR':([2,7,26,65,97,],[7,26,65,97,116,]),'EWITH':([2,7,26,65,97,116,],[8,28,67,99,118,133,]),'EQUALS':([2,7,10,26,30,65,69,97,101,116,120,135,],[9,29,40,68,74,100,106,119,125,134,140,150,]),'NOT':([2,7,26,65,97,116,],[10,30,69,101,120,135,]),'CONTAINS':([2,7,10,26,30,65,69,97,101,116,120,135,],[11,31,41,70,75,102,107,121,126,136,141,151,]),'IN':([2,7,10,30,],[12,32,42,76,]),'GT':([2,7,],[13,33,]),'GTE':([2,7,],[14,34,]),'LT':([2,7,],[15,35,]),'LTE':([2,7,],[16,36,]),'CIDR':([2,10,],[17,43,]),'EXISTS':([2,10,],[18,44,]),'REGEXP':([2,10,],[19,45,]),'IS':([2,],[20,]),'BETWEEN':([2,10,],[21,46,]),'STRING':([6,8,9,11,17,19,21,27,28,29,31,40,41,43,45,46,66,67,68,70,74,75,98,99,100,102,106,107,117,118,119,121,125,126,132,133,134,136,140,141,150,151,],[25,37,38,47,58,59,61,71,72,73,77,87,89,92,93,94,103,104,105,108,110,111,122,123,124,127,129,130,137,138,139,142,144,145,147,148,149,152,154,155,157,158,]),'NUMBER':([9,13,14,15,16,33,34,35,36,40,],[39,50,52,54,56,79,81,83,85,88,]),'ARRAY':([11,12,32,41,42,70,75,76,102,107,121,126,136,141,151,],[48,49,78,90,91,109,112,113,128,131,143,146,153,156,159,]),'FLOAT':([13,14,15,16,33,34,35,36,],[51,53,55,57,80,82,84,86,]),'BOOL':([20,],[60,]),}

_lr_action = {}
for _k, _v in _lr_action_items.items():
   for _x,_y in zip(_v[0],_v[1]):
      if not _x in _lr_action:  _lr_action[_x] = {}
      _lr_action[_x][_k] = _y
del _lr_action_items

_lr_goto_items = {'expression':([0,3,4,5,63,64,],[1,22,23,24,95,96,]),}

_lr_goto = {}
for _k, _v in _lr_goto_items.items():
   for _x, _y in zip(_v[0], _v[1]):
       if not _x in _lr_goto: _lr_goto[_x] = {}
       _lr_goto[_x][_k] = _y
del _lr_goto_items
_lr_productions = [
  ("S' -> expression","S'",1,None,None,None),
  ('expression -> target','expression',1,'p_expression','rql_experiment2.py',177),
  ('expression -> expression OR expression','expression',3,'p_expression_or','rql_experiment2.py',181),
  ('expression -> expression AND expression','expression',3,'p_expression_and','rql_experiment2.py',185),
  ('expression -> LPAREN expression RPAREN','expression',3,'p_expression_singlet','rql_experiment2.py',189),
  ('expression -> LPAREN expression AND expression RPAREN','expression',5,'p_expression_and_group','rql_experiment2.py',193),
  ('expression -> LPAREN expression OR expression RPAREN','expression',5,'p_expression_or_group','rql_experiment2.py',197),
  ('expression -> target SWITH STRING','expression',3,'p_expression_startswith','rql_experiment2.py',201),
  ('expression -> target MUTATOR SWITH STRING','expression',4,'p_expression_startswith','rql_experiment2.py',202),
  ('expression -> target MUTATOR MUTATOR SWITH STRING','expression',5,'p_expression_startswith','rql_experiment2.py',203),
  ('expression -> target MUTATOR MUTATOR MUTATOR SWITH STRING','expression',6,'p_expression_startswith','rql_experiment2.py',204),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING','expression',7,'p_expression_startswith','rql_experiment2.py',205),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR SWITH STRING','expression',8,'p_expression_startswith','rql_experiment2.py',206),
  ('expression -> target EWITH STRING','expression',3,'p_expression_endswith','rql_experiment2.py',212),
  ('expression -> target MUTATOR EWITH STRING','expression',4,'p_expression_endswith','rql_experiment2.py',213),
  ('expression -> target MUTATOR MUTATOR EWITH STRING','expression',5,'p_expression_endswith','rql_experiment2.py',214),
  ('expression -> target MUTATOR MUTATOR MUTATOR EWITH STRING','expression',6,'p_expression_endswith','rql_experiment2.py',215),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING','expression',7,'p_expression_endswith','rql_experiment2.py',216),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EWITH STRING','expression',8,'p_expression_endswith','rql_experiment2.py',217),
  ('expression -> target EQUALS STRING','expression',3,'p_expression_match','rql_experiment2.py',223),
  ('expression -> target MUTATOR EQUALS STRING','expression',4,'p_expression_match','rql_experiment2.py',224),
  ('expression -> target MUTATOR MUTATOR EQUALS STRING','expression',5,'p_expression_match','rql_experiment2.py',225),
  ('expression -> target MUTATOR MUTATOR MUTATOR EQUALS STRING','expression',6,'p_expression_match','rql_experiment2.py',226),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR EQUALS STRING','expression',7,'p_expression_match','rql_experiment2.py',227),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR EQUALS STRING','expression',8,'p_expression_match','rql_experiment2.py',228),
  ('expression -> target EQUALS NUMBER','expression',3,'p_expression_match','rql_experiment2.py',229),
  ('expression -> target NOT EQUALS STRING','expression',4,'p_expression_match','rql_experiment2.py',230),
  ('expression -> target MUTATOR NOT EQUALS STRING','expression',5,'p_expression_match','rql_experiment2.py',231),
  ('expression -> target MUTATOR MUTATOR NOT EQUALS STRING','expression',6,'p_expression_match','rql_experiment2.py',232),
  ('expression -> target MUTATOR MUTATOR MUTATOR NOT EQUALS STRING','expression',7,'p_expression_match','rql_experiment2.py',233),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR NOT EQUALS STRING','expression',8,'p_expression_match','rql_experiment2.py',234),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT EQUALS STRING','expression',9,'p_expression_match','rql_experiment2.py',235),
  ('expression -> target NOT EQUALS NUMBER','expression',4,'p_expression_match','rql_experiment2.py',236),
  ('expression -> target CONTAINS STRING','expression',3,'p_expression_contains','rql_experiment2.py',250),
  ('expression -> target MUTATOR CONTAINS STRING','expression',4,'p_expression_contains','rql_experiment2.py',251),
  ('expression -> target MUTATOR MUTATOR CONTAINS STRING','expression',5,'p_expression_contains','rql_experiment2.py',252),
  ('expression -> target MUTATOR MUTATOR MUTATOR CONTAINS STRING','expression',6,'p_expression_contains','rql_experiment2.py',253),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS STRING','expression',7,'p_expression_contains','rql_experiment2.py',254),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS STRING','expression',8,'p_expression_contains','rql_experiment2.py',255),
  ('expression -> target NOT CONTAINS STRING','expression',4,'p_expression_contains','rql_experiment2.py',256),
  ('expression -> target MUTATOR NOT CONTAINS STRING','expression',5,'p_expression_contains','rql_experiment2.py',257),
  ('expression -> target MUTATOR MUTATOR NOT CONTAINS STRING','expression',6,'p_expression_contains','rql_experiment2.py',258),
  ('expression -> target MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING','expression',7,'p_expression_contains','rql_experiment2.py',259),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING','expression',8,'p_expression_contains','rql_experiment2.py',260),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS STRING','expression',9,'p_expression_contains','rql_experiment2.py',261),
  ('expression -> target CONTAINS ARRAY','expression',3,'p_expression_contains','rql_experiment2.py',262),
  ('expression -> target MUTATOR MUTATOR CONTAINS ARRAY','expression',5,'p_expression_contains','rql_experiment2.py',263),
  ('expression -> target MUTATOR MUTATOR MUTATOR CONTAINS ARRAY','expression',6,'p_expression_contains','rql_experiment2.py',264),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS ARRAY','expression',7,'p_expression_contains','rql_experiment2.py',265),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR CONTAINS ARRAY','expression',8,'p_expression_contains','rql_experiment2.py',266),
  ('expression -> target NOT CONTAINS ARRAY','expression',4,'p_expression_contains','rql_experiment2.py',267),
  ('expression -> target MUTATOR NOT CONTAINS ARRAY','expression',5,'p_expression_contains','rql_experiment2.py',268),
  ('expression -> target MUTATOR MUTATOR NOT CONTAINS ARRAY','expression',6,'p_expression_contains','rql_experiment2.py',269),
  ('expression -> target MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY','expression',7,'p_expression_contains','rql_experiment2.py',270),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY','expression',8,'p_expression_contains','rql_experiment2.py',271),
  ('expression -> target MUTATOR MUTATOR MUTATOR MUTATOR MUTATOR NOT CONTAINS ARRAY','expression',9,'p_expression_contains','rql_experiment2.py',272),
  ('expression -> target IN ARRAY','expression',3,'p_expression_in','rql_experiment2.py',287),
  ('expression -> target MUTATOR IN ARRAY','expression',4,'p_expression_in','rql_experiment2.py',288),
  ('expression -> target NOT IN ARRAY','expression',4,'p_expression_in','rql_experiment2.py',289),
  ('expression -> target MUTATOR NOT IN ARRAY','expression',5,'p_expression_in','rql_experiment2.py',290),
  ('expression -> target GT NUMBER','expression',3,'p_expression_math_op','rql_experiment2.py',305),
  ('expression -> target GTE NUMBER','expression',3,'p_expression_math_op','rql_experiment2.py',306),
  ('expression -> target LT NUMBER','expression',3,'p_expression_math_op','rql_experiment2.py',307),
  ('expression -> target LTE NUMBER','expression',3,'p_expression_math_op','rql_experiment2.py',308),
  ('expression -> target MUTATOR GT NUMBER','expression',4,'p_expression_math_op','rql_experiment2.py',309),
  ('expression -> target MUTATOR GTE NUMBER','expression',4,'p_expression_math_op','rql_experiment2.py',310),
  ('expression -> target MUTATOR LT NUMBER','expression',4,'p_expression_math_op','rql_experiment2.py',311),
  ('expression -> target MUTATOR LTE NUMBER','expression',4,'p_expression_math_op','rql_experiment2.py',312),
  ('expression -> target GT FLOAT','expression',3,'p_expression_math_op','rql_experiment2.py',313),
  ('expression -> target GTE FLOAT','expression',3,'p_expression_math_op','rql_experiment2.py',314),
  ('expression -> target LT FLOAT','expression',3,'p_expression_math_op','rql_experiment2.py',315),
  ('expression -> target LTE FLOAT','expression',3,'p_expression_math_op','rql_experiment2.py',316),
  ('expression -> target MUTATOR GT FLOAT','expression',4,'p_expression_math_op','rql_experiment2.py',317),
  ('expression -> target MUTATOR GTE FLOAT','expression',4,'p_expression_math_op','rql_experiment2.py',318),
  ('expression -> target MUTATOR LT FLOAT','expression',4,'p_expression_math_op','rql_experiment2.py',319),
  ('expression -> target MUTATOR LTE FLOAT','expression',4,'p_expression_math_op','rql_experiment2.py',320),
  ('expression -> target CIDR STRING','expression',3,'p_expression_in_cidr','rql_experiment2.py',328),
  ('expression -> target NOT CIDR STRING','expression',4,'p_expression_in_cidr','rql_experiment2.py',329),
  ('expression -> target EXISTS','expression',2,'p_expression_exists','rql_experiment2.py',346),
  ('expression -> target NOT EXISTS','expression',3,'p_expression_exists','rql_experiment2.py',347),
  ('expression -> target REGEXP STRING','expression',3,'p_expression_regexp','rql_experiment2.py',361),
  ('expression -> target NOT REGEXP STRING','expression',4,'p_expression_regexp','rql_experiment2.py',362),
  ('expression -> target IS BOOL','expression',3,'p_expression_is','rql_experiment2.py',377),
  ('expression -> target BETWEEN STRING','expression',3,'p_expression_between','rql_experiment2.py',381),
  ('expression -> target NOT BETWEEN STRING','expression',4,'p_expression_between','rql_experiment2.py',382),
]
