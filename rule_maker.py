
from skfuzzy import control as ctrl

class RuleMaker:
    
    @staticmethod
    def _make_1n_rules(ants, cons, ants_terms, cons_terms_foo):
        rules = []
        ant = ants[0]
        terms = ants_terms[0]
        for ant_term in terms:
            rules.append(ctrl.Rule(ant[ant_term], cons[cons_terms_foo(ant_term)]))
            
        return rules
    
    @staticmethod
    def _make_2n_rules(ants, cons, ants_terms, cons_terms_foo):
        rules = []
        for ant_term_1 in ants_terms[0]:
            for ant_term_2 in ants_terms[1]:
                rules.append(ctrl.Rule(ants[0][ant_term_1] & ants[1][ant_term_2], cons[cons_terms_foo(ant_term_1, ant_term_2)]))
                
        return rules
    
    @staticmethod
    def _make_3n_rules(ants, cons, ants_terms, cons_terms_foo):
        rules = []
        for ant_term_1 in ants_terms[0]:
            for ant_term_2 in ants_terms[1]:
                for ant_term_3 in ants_terms[2]:
                    rules.append(ctrl.Rule(ants[0][ant_term_1] & ants[1][ant_term_2] & ants[2][ant_term_3], cons[cons_terms_foo(ant_term_1, ant_term_2, ant_term_3)]))
                
        return rules

    def make_rules(self, ants, cons, ants_terms, foo):
        ants_size = len(ants)
        if ants_size == 1:
            return RuleMaker._make_1n_rules(ants, cons, ants_terms, foo)
        if ants_size == 2:
            return RuleMaker._make_2n_rules(ants, cons, ants_terms, foo)
        if ants_size == 3:
            return RuleMaker._make_3n_rules(ants, cons, ants_terms, foo)